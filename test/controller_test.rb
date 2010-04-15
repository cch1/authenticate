require File.dirname(__FILE__) + '/test_helper.rb'

class ControllerTest < ActionController::TestCase
  fixtures :users

  include Authenticate::AuthenticatedTestHelper

  tests UsersController

  def test_should_start_unauthenticated
    assert_nil @controller.send(:authenticated?)
    assert_nil @controller.send(:authentication_method)
  end

  # Regardless of the presence/absence of a filter, it should be possible to authenticate.
  def test_should_authenticate_implicitly
    users(:chris).generate_security_token
    get :status, :security_token => users(:chris).security_token
    assert users(:chris), @controller.send(:authenticated?)
  end

  def test_should_login_manually
    post :login_simple, :user => {:login => users(:chris).login, :password => 'Cruft'}
    assert @controller.send(:logged_in?), 'User should be logged in.'
    assert_equal users(:chris), @controller.send(:current_user)
    assert_equal :manual, @request.session[:authentication_method]
  end

  def test_should_login
    post :login, :credentials => {:login => users(:chris).login, :password => 'Cruft'}
    assert @controller.send(:logged_in?), 'User should be logged in.'
    assert_equal users(:chris), @controller.send(:current_user)
    assert_equal :http_post, @request.session[:authentication_method]
  end

  def test_should_remember_me
    post :login, :credentials => {:login => users(:chris).login, :password => 'Cruft'}, :remember_me => '1'
    assert users(:chris).reload.security_token
    assert_equal users(:chris).reload.security_token, cookies["authentication_token"]
  end

  def test_should_logout
    login_as(:chris)
    delete :logout
    assert !@controller.send(:logged_in?), 'User should not be logged in.'
  end

  def test_should_require_authentication_by_default
    assert_raises Authenticate::AuthenticationError do
      get :new
    end
    assert !@controller.send(:logged_in?), "User should not be logged in."
  end

  def test_should_authenticate_by_valid_token
    users(:chris).generate_security_token
    get :new, :security_token => users(:chris).security_token
    assert @controller.send(:logged_in?), "User should be logged in."
    assert_equal :token, @controller.instance_variable_get(:@authentication_method)
    assert_equal :token, @request.session[:authentication_method]
  end

  def test_should_not_authenticate_by_invalid_token
    assert_raises Authenticate::AuthenticationError do
      get :new, :security_token => 'InvalidToken'
    end
    assert !@controller.send(:logged_in?), "User should not be logged in."
    assert_nil @controller.instance_variable_get(:@authentication_method)
  end

  def test_should_not_authenticate_by_expired_token
    users(:chris).generate_security_token
    users(:chris).update_attribute :token_expiry, 5.minutes.ago
    assert_raises Authenticate::AuthenticationError do
      get :new, :security_token => users(:chris).security_token
    end
    assert !@controller.send(:logged_in?), "User should not be logged in."
    assert_nil @controller.instance_variable_get(:@authentication_method)
  end

  def test_should_authenticate_by_token_even_with_conflicting_session
    @request.session[:user] = users(:pascale).id
    users(:chris).generate_security_token
    get :new, :security_token => users(:chris).security_token
    assert @controller.send(:logged_in?), "User should be logged in."
    assert_equal :token, @controller.instance_variable_get(:@authentication_method)
    assert_equal :token, @request.session[:authentication_method]
    assert_equal users(:chris).id, @request.session[:user]
  end

  def test_should_authenticate_by_session
    @request.session[:user] = users(:chris).id
    get :new
    assert @controller.send(:logged_in?), "User should be logged in."
    assert_equal :session, @controller.instance_variable_get(:@authentication_method)
    assert_equal :session, @request.session[:authentication_method]
  end

  def test_should_not_authenticate_by_nil_session
    @request.session[:user] = nil
    assert_raises Authenticate::AuthenticationError do
      get :new
    end
    assert !@controller.send(:logged_in?), "User should not be logged in."
    assert_nil @controller.instance_variable_get(:@authentication_method)
  end

  def test_should_authenticate_by_HTTP_AUTHORIZATION
    @request.env['HTTP_AUTHORIZATION'] = ActionController::HttpAuthentication::Basic.encode_credentials(users(:chris).login, 'Cruft')
    get :new
    assert @controller.send(:logged_in?), "User should be logged in."
    assert_equal :http_authentication, @controller.instance_variable_get(:@authentication_method)
    assert_equal :http_authentication, @request.session[:authentication_method]
  end

  def test_should_not_authenticate_by_invalid_HTTP_AUTHORIZATION
    @request.env['HTTP_AUTHORIZATION'] = ActionController::HttpAuthentication::Basic.encode_credentials(users(:chris).login, 'NotCruft')
    assert_raises Authenticate::AuthenticationError do
      head :new
    end
    assert !@controller.send(:logged_in?), "User should not be logged in."
    assert_nil @controller.instance_variable_get(:@authentication_method)
  end

  def test_should_authenticate_by_cookie
    users(:chris).generate_security_token
    @request.cookies["authentication_token"] = cookie_for(:chris)
    head :new
    assert @controller.send(:logged_in?), "User should be logged in."
    assert_equal :cookie, @controller.instance_variable_get(:@authentication_method)
    assert_equal :cookie, @request.session[:authentication_method]
  end

  def test_should_recognize_cookie_persistence_without_explicit_login
    users(:chris).generate_security_token
    @request.cookies["authentication_token"] = cookie_for(:chris)
    head :status
    assert @controller.send(:logged_in?), "User should be logged in."
    assert_equal :cookie, @controller.instance_variable_get(:@authentication_method)
  end

  def test_should_not_authenticate_by_cookie_with_invalid_token
    users(:chris).generate_security_token
    @request.cookies["authentication_token"] = auth_token('invalid_auth_token')
    assert_raises Authenticate::AuthenticationError do
      head :new
    end
    assert !@controller.send(:logged_in?), "User should not be logged in."
    assert_nil @controller.instance_variable_get(:@authentication_method)
  end

  def test_should_not_authenticate_by_cookie_with_expired_token
    users(:chris).generate_security_token
    users(:chris).update_attribute :token_expiry, 5.minutes.ago
    @request.cookies["authentication_token"] = cookie_for(:chris)
    assert_raises Authenticate::AuthenticationError do
      head :new
    end
    assert !@controller.send(:logged_in?), "User should not be logged in."
    assert_nil @controller.instance_variable_get(:@authentication_method)
  end

  def test_should_generate_remember_me_cookie_upon_authentication
    post :login, :credentials => {:login => users(:chris).login, :password => 'Cruft'}, :remember_me => '1'
    # Note that that cookies method below is not the same as the one used in ActionController -it is specific to the
    # test process and always returns an array of values, even if the value is a singleton.  Neither the reader nor the
    # writer in ActionController behave this way.
    assert token = cookies["authentication_token"]
    assert_equal users(:chris), User.authenticate_by_token(token)
  end

  # Even when fed garbage, the authentication process should trap exceptions
  # to ensure that an infinite redirection loop is not spawned.
  def test_should_trap_exceptions_during_authentication
    @request.session[:user] = -1
    assert_nothing_raised do
      get :status
    end
    assert !@controller.send(:authenticated?), "User should not be authenticated."
    assert_nil @controller.instance_variable_get(:@authentication_method)
  end

  uses_mocha 'mocking OpenID library' do
    def test_should_begin_authentication_by_OpenID
      identity_url = 'http://openid-provider.appspot.com/corlett.chris/'
      request = mock do
        stubs(:return_to_args).returns(Hash.new)
        expects(:redirect_url).returns("http://somewhere.com/?openid.identity=#{identity_url}")
      end
      ::OpenID::Consumer.any_instance.expects(:begin).returns(request)

      post :login, :credentials => {:login => identity_url}
      assert !@controller.send(:logged_in?), "User should not be authenticated."
      assert_response :redirect
      assert_match /#{identity_url}/, @response.redirected_to
    end

    def test_should_begin_authentication_by_OpenID_with_SSL
      identity_url = 'https://openid-provider.appspot.com/corlett.chris/'
      request = mock do
        stubs(:return_to_args).returns(Hash.new)
        expects(:redirect_url).returns("http://somewhere.com/?openid.identity=#{identity_url}")
      end
      ::OpenID::Consumer.any_instance.expects(:begin).returns(request)

      post :login, :credentials => {:login => identity_url}
      assert !@controller.send(:logged_in?), "User should not be authenticated."
      assert_response :redirect
      assert_match /#{identity_url}/, @response.redirected_to
    end

    def test_should_complete_authentication_by_OpenID
      identity_url = users(:chris).identity_url
      response = mock do
        stubs(:status).returns(::OpenID::Consumer::SUCCESS)
        stubs(:identity_url).returns(identity_url)
      end
      ::OpenID::Consumer.any_instance.expects(:complete).returns(response)

      params = {"open_id_complete"=>"1", "openid.sig"=>"TZK7lEXXMBME5opcsUqCd3s2BB4=", "openid.return_to"=>"http://test.com/home?open_id_complete=1&openid1_claimed_id=http%3A%2F%2Fchris.myopenid.com%2F&rp_nonce=2008-09-26T19%3A39%3A16ZTMgPw9", "openid.mode"=>"id_res", "openid.op_endpoint"=>"http://www.myopenid.com/server", "rp_nonce"=>"2008-09-26T19:39:16ZTMgPw9", "openid.response_nonce"=>"2008-09-26T19:39:17Z0fqKSy", "openid.identity"=>"http://chris.myopenid.com/", "openid1_claimed_id"=>"http://chris.myopenid.com/", "openid.signed"=>"assoc_handle,identity,mode,op_endpoint,response_nonce,return_to,signed", "openid.assoc_handle"=>"{HMAC-SHA1}{48da926b}{VLBz+Q==}"}
      get :home, params
      assert @controller.send(:logged_in?), "User should be logged in."
      assert_response :success
    end
  end

  # Depending on client behavior, it's possible that a previously deleted cookie (indicated by an empty string) could
  # be re-presented to the server.  At a minimum, this behavior has been observed in Rails' integration tests.
  def test_handle_deleted_authentication_cookie
    @request.cookies["authentication_token"] = ''
    get :login_simple, {:user => {:login => 'cch1'}}
    assert @controller.send(:logged_in?), "User should be logged in."
    assert cookies["authentication_token"] == "" || cookies["authentication_token"].nil?
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
