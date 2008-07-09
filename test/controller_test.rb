require File.dirname(__FILE__) + '/test_helper.rb'
require File.dirname(__FILE__) + '/lib/users_controller.rb'

class ControllerTest < ActionController::TestCase
  fixtures :users
  
  tests UsersController

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
  end

  test 'should not authenticate by invalid token' do
    assert_raises Authenticate::AuthenticationError do
      get :new, :security_token => 'InvalidToken'
    end
    assert !@controller.send(:logged_in?), "User should not be authenticated."
  end

  test 'should not authenticate by expired token' do
    users(:chris).generate_security_token
    users(:chris).update_attribute :token_expiry, 5.minutes.ago
    assert_raises Authenticate::AuthenticationError do
      get :new, :security_token => users(:chris).security_token
    end
    assert !@controller.send(:logged_in?), "User should not be authenticated."
  end

  test 'should authenticate by session' do
    @request.session[:user] = users(:chris).id
    get :new
    assert @controller.send(:logged_in?), "User should be authenticated."
  end

  test 'should not authenticate by nil session' do
    @request.session[:user] = nil
    assert_raises Authenticate::AuthenticationError do
      get :new
    end
    assert !@controller.send(:logged_in?), "User should not be authenticated."
  end

  test 'should authenticate by HTTP_AUTHORIZATION' do
    @request.env['HTTP_AUTHORIZATION'] = ActionController::HttpAuthentication::Basic.encode_credentials(users(:chris).login, 'Cruft')
    get :new
    assert @controller.send(:logged_in?), "User should be authenticated."
  end

  test 'should not authenticate by invalid HTTP_AUTHORIZATION' do
    @request.env['HTTP_AUTHORIZATION'] = ActionController::HttpAuthentication::Basic.encode_credentials(users(:chris).login, 'NotCruft')
    assert_raises Authenticate::AuthenticationError do
      head :new
    end
    assert !@controller.send(:logged_in?), "User should not be authenticated."
  end

  test 'should authenticate by cookie' do
    users(:chris).generate_security_token
    @request.cookies["authentication_token"] = cookie_for(:chris)
    head :new
    assert @controller.send(:logged_in?), "User should be authenticated."
  end

  test 'should not authenticate by cookie with invalid token' do
    users(:chris).generate_security_token
    @request.cookies["authentication_token"] = auth_token('invalid_auth_token')
    assert_raises Authenticate::AuthenticationError do
      head :new
    end
    assert !@controller.send(:logged_in?), "User should not be authenticated."
  end

  test 'should not authenticate by cookie with expired token' do
    users(:chris).generate_security_token
    users(:chris).update_attribute :token_expiry, 5.minutes.ago
    @request.cookies["authentication_token"] = cookie_for(:chris)
    assert_raises Authenticate::AuthenticationError do
      head :new
    end
    assert !@controller.send(:logged_in?), "User should not be authenticated."
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
