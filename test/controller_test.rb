require File.dirname(__FILE__) + '/test_helper.rb'

class ControllerTest < ActionController::TestCase
  fixtures :users
  
  tests UsersController
  
  def test_should_start_unauthenticated
    assert_nil User.current
    assert_nil @controller.send(:current_user)    
  end
  
  def test_should_login
    post :login, :user => {:login => users(:chris).login}
    assert @controller.send(:logged_in?), 'User should be authenticated.'
    assert_equal users(:chris), User.current
    assert_equal users(:chris), @controller.send(:current_user)
    assert_equal :unknown, @request.session[:authentication_method]
  end

  def test_should_logout
    post :login, :user => {:login => users(:chris).login}
    delete :logout
    assert !@controller.send(:logged_in?), 'User should not be authenticated.'
    assert_nil User.current
    assert_nil @controller.send(:current_user)    
  end

  def test_should_require_authentication_by_default
    assert_raises Authenticate::AuthenticationError do
      get :new
    end
    assert !@controller.send(:logged_in?), "User should not be authenticated."
  end
  
  def test_should_authenticate_by_valid_token
    users(:chris).generate_security_token
    get :new, :security_token => users(:chris).security_token
    assert @controller.send(:logged_in?), "User should be authenticated."
    assert_equal :token, @controller.instance_variable_get(:@authentication_method)
    assert_equal :token, @request.session[:authentication_method]
  end

  def test_should_not_authenticate_by_invalid_token
    assert_raises Authenticate::AuthenticationError do
      get :new, :security_token => 'InvalidToken'
    end
    assert !@controller.send(:logged_in?), "User should not be authenticated."
    assert_nil @controller.instance_variable_get(:@authentication_method)
  end

  def test_should_not_authenticate_by_expired_token
    users(:chris).generate_security_token
    users(:chris).update_attribute :token_expiry, 5.minutes.ago
    assert_raises Authenticate::AuthenticationError do
      get :new, :security_token => users(:chris).security_token
    end
    assert !@controller.send(:logged_in?), "User should not be authenticated."
    assert_nil @controller.instance_variable_get(:@authentication_method)
  end
  
  def test_should_authenticate_by_token_even_with_conflicting_session
    @request.session[:user] = users(:pascale).id
    users(:chris).generate_security_token
    get :new, :security_token => users(:chris).security_token
    assert @controller.send(:logged_in?), "User should be authenticated."
    assert_equal :token, @controller.instance_variable_get(:@authentication_method)
    assert_equal :token, @request.session[:authentication_method]   
    assert_equal users(:chris).id, @request.session[:user]
  end

  def test_should_authenticate_by_session
    @request.session[:user] = users(:chris).id
    get :new
    assert @controller.send(:logged_in?), "User should be authenticated."
    assert_equal :session, @controller.instance_variable_get(:@authentication_method)
    assert_equal :session, @request.session[:authentication_method]
  end

  def test_should_not_authenticate_by_nil_session
    @request.session[:user] = nil
    assert_raises Authenticate::AuthenticationError do
      get :new
    end
    assert !@controller.send(:logged_in?), "User should not be authenticated."
    assert_nil @controller.instance_variable_get(:@authentication_method)
  end

  def test_should_authenticate_by_HTTP_AUTHORIZATION
    @request.env['HTTP_AUTHORIZATION'] = ActionController::HttpAuthentication::Basic.encode_credentials(users(:chris).login, 'Cruft')
    get :new
    assert @controller.send(:logged_in?), "User should be authenticated."
    assert_equal :http_authentication, @controller.instance_variable_get(:@authentication_method)
    assert_equal :http_authentication, @request.session[:authentication_method]
  end

  def test_should_not_authenticate_by_invalid_HTTP_AUTHORIZATION
    @request.env['HTTP_AUTHORIZATION'] = ActionController::HttpAuthentication::Basic.encode_credentials(users(:chris).login, 'NotCruft')
    assert_raises Authenticate::AuthenticationError do
      head :new
    end
    assert !@controller.send(:logged_in?), "User should not be authenticated."
    assert_nil @controller.instance_variable_get(:@authentication_method)
  end

  def test_should_authenticate_by_cookie
    users(:chris).generate_security_token
    @request.cookies["authentication_token"] = cookie_for(:chris)
    head :new
    assert @controller.send(:logged_in?), "User should be authenticated."
    assert_equal :cookie, @controller.instance_variable_get(:@authentication_method)
    assert_equal :cookie, @request.session[:authentication_method]
  end

  def test_should_not_authenticate_by_cookie_with_invalid_token
    users(:chris).generate_security_token
    @request.cookies["authentication_token"] = auth_token('invalid_auth_token')
    assert_raises Authenticate::AuthenticationError do
      head :new
    end
    assert !@controller.send(:logged_in?), "User should not be authenticated."
    assert_nil @controller.instance_variable_get(:@authentication_method)
  end

  def test_should_not_authenticate_by_cookie_with_expired_token
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
