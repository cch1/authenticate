require File.dirname(__FILE__) + '/test_helper.rb'
require File.dirname(__FILE__) + '/lib/users_controller.rb'

class ControllerTest < ActionController::TestCase
  fixtures :users
  
  tests UsersController
  
  test 'should start unauthenticated' do
    assert_nil User.current
    assert_nil @controller.send(:current_user)    
  end
  
  test 'should login' do
    post :login, :user => {:login => users(:chris).login}
    assert @controller.send(:logged_in?), 'User should be authenticated.'
    assert_equal users(:chris), User.current
    assert_equal users(:chris), @controller.send(:current_user)
    assert_equal :unknown, @request.session[:authentication_method]
  end

  test 'should logout' do
    post :login, :user => {:login => users(:chris).login}
    delete :logout
    assert !@controller.send(:logged_in?), 'User should not be authenticated.'
    assert_nil User.current
    assert_nil @controller.send(:current_user)    
  end

  test 'should require authentication by default' do
    assert_raises Authenticate::AuthenticationError do
      get :new
    end
    assert !@controller.send(:logged_in?), "User should not be authenticated."
  end
  
  test 'should authenticate by valid token' do
    users(:chris).generate_security_token
    get :new, :security_token => users(:chris).security_token
    assert @controller.send(:logged_in?), "User should be authenticated."
    assert_equal :token, @controller.instance_variable_get(:@authentication_method)
    assert_equal :token, @request.session[:authentication_method]
  end

  test 'should not authenticate by invalid token' do
    assert_raises Authenticate::AuthenticationError do
      get :new, :security_token => 'InvalidToken'
    end
    assert !@controller.send(:logged_in?), "User should not be authenticated."
    assert_nil @controller.instance_variable_get(:@authentication_method)
  end

  test 'should not authenticate by expired token' do
    users(:chris).generate_security_token
    users(:chris).update_attribute :token_expiry, 5.minutes.ago
    assert_raises Authenticate::AuthenticationError do
      get :new, :security_token => users(:chris).security_token
    end
    assert !@controller.send(:logged_in?), "User should not be authenticated."
    assert_nil @controller.instance_variable_get(:@authentication_method)
  end
  
  test 'should authenticate by token even with conflicting session' do
    @request.session[:user] = users(:pascale).id
    users(:chris).generate_security_token
    get :new, :security_token => users(:chris).security_token
    assert @controller.send(:logged_in?), "User should be authenticated."
    assert_equal :token, @controller.instance_variable_get(:@authentication_method)
    assert_equal :token, @request.session[:authentication_method]   
    assert_equal users(:chris).id, @request.session[:user]
  end

  test 'should authenticate by session' do
    @request.session[:user] = users(:chris).id
    get :new
    assert @controller.send(:logged_in?), "User should be authenticated."
    assert_equal :session, @controller.instance_variable_get(:@authentication_method)
    assert_equal :session, @request.session[:authentication_method]
  end

  test 'should not authenticate by nil session' do
    @request.session[:user] = nil
    assert_raises Authenticate::AuthenticationError do
      get :new
    end
    assert !@controller.send(:logged_in?), "User should not be authenticated."
    assert_nil @controller.instance_variable_get(:@authentication_method)
  end

  test 'should authenticate by HTTP_AUTHORIZATION' do
    @request.env['HTTP_AUTHORIZATION'] = ActionController::HttpAuthentication::Basic.encode_credentials(users(:chris).login, 'Cruft')
    get :new
    assert @controller.send(:logged_in?), "User should be authenticated."
    assert_equal :http_authentication, @controller.instance_variable_get(:@authentication_method)
    assert_equal :http_authentication, @request.session[:authentication_method]
  end

  test 'should not authenticate by invalid HTTP_AUTHORIZATION' do
    @request.env['HTTP_AUTHORIZATION'] = ActionController::HttpAuthentication::Basic.encode_credentials(users(:chris).login, 'NotCruft')
    assert_raises Authenticate::AuthenticationError do
      head :new
    end
    assert !@controller.send(:logged_in?), "User should not be authenticated."
    assert_nil @controller.instance_variable_get(:@authentication_method)
  end

  test 'should authenticate by cookie' do
    users(:chris).generate_security_token
    @request.cookies["authentication_token"] = cookie_for(:chris)
    head :new
    assert @controller.send(:logged_in?), "User should be authenticated."
    assert_equal :cookie, @controller.instance_variable_get(:@authentication_method)
    assert_equal :cookie, @request.session[:authentication_method]
  end

  test 'should not authenticate by cookie with invalid token' do
    users(:chris).generate_security_token
    @request.cookies["authentication_token"] = auth_token('invalid_auth_token')
    assert_raises Authenticate::AuthenticationError do
      head :new
    end
    assert !@controller.send(:logged_in?), "User should not be authenticated."
    assert_nil @controller.instance_variable_get(:@authentication_method)
  end

  test 'should not authenticate by cookie with expired token' do
    users(:chris).generate_security_token
    users(:chris).update_attribute :token_expiry, 5.minutes.ago
    @request.cookies["authentication_token"] = cookie_for(:chris)
    assert_raises Authenticate::AuthenticationError do
      head :new
    end
    assert !@controller.send(:logged_in?), "User should not be authenticated."
    assert_nil @controller.instance_variable_get(:@authentication_method)
  end

  protected
    # Build a cookie with the given authentication token.
    def auth_token(token)
      CGI::Cookie.new('name' => 'authentication_token', 'value' => token)
    end
    
    # Build a cookie containing the security token of a given user.
    def cookie_for(user)
      auth_token(users(user).security_token)
    end
end
