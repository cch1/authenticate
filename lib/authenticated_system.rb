module Authenticate
  module AuthenticatedSystem
    
    protected

    attr_reader :authentication_method

    # Assign the current user manually and persist his authentication.
    def current_user=(u)
      @authentication_method ||= :manual
      @authenticated_user = u
      persist_authentication(u)
    end
    
    # Persist the given user's authentication across requests.
    # Semantically, this could be interpreted as "login" or "logout" operation.
    # TODO: Test behavior with sessions and cookies disabled.
    def persist_authentication(u)
      raise "Unknown authentication method." unless authentication_method
      if u
        # Could regenerate token instead for nonce behavior
        cookies[:authentication_token] = { :value => u.security_token , :expires => u.bump_token_expiry } if cookies[:authentication_token] 
        session[:authentication_method] ||= authentication_method  # Record authentication method used at login.
        logger.info "Authentication: #{u.login} logged in via #{authentication_method}." unless session[:user] == u.id
      else # remove persistence
        cookies.delete :authentication_token
        session[:authentication_method] = nil
        logger.info "Authentication: User logged out (#{session[:user]})."
      end
      @authentication_persisted = true
      session[:user] = u && u.id
    end

    # Logged in is the state in which the current user is persisted.  Note that Rails (through 2.2) does not
    # (practically) allow the reading of written/outbound cookies, making it difficult to rigorously determine
    # our intent to persist authentication through to the next request.  Instead, we assume that authentication
    # with an inherently persistent method will endure and thus that any auth cookie will not expire.
    def logged_in?
      @authentication_persisted ? session[:user] : authenticated_user && [:session, :cookie].include?(authentication_method)
    end
    
    # Checks for an authenticated user, implicitly logging him in if present.
    def authentication
      returning authenticated_user do |u|
        u ? logger.debug("Authentication: #{u.login} authenticated via #{authentication_method}.") : handle_authentication_failure
        persist_authentication(u)
      end
    end
    
    # Manage response to authentication failure.  Override this method in application.rb.
    def handle_authentication_failure(message = nil)
      raise Authenticate::AuthenticationError, message
    end
    alias access_denied handle_authentication_failure
  
    # Allows current_user and logged_in? to be used in views.  Also sets up a rescue response where supported.
    def self.included(base)
      ActionController::Base.send :helper_method, :current_user, :logged_in?
      if base.respond_to?(:rescue_responses)
        base.rescue_responses['Authenticate::AuthenticationError'] = :unauthorized # Poorly named -it really is intended for 'unauthenticated'.
      end
    end
    
    # Authenticate the user based on provided credentials.  Credentials object can include userid, password and OpenID URLs.
    # When the user is authenticated, the associated block is executed.  This is a high-level construct, and it takes care 
    # of login (logging and persistence).  If no parameters are provided, it attempts to extract authentication information
    # from the current request.
    # TODO: The callback from the provider will be an HTTP GET.  To add support for POST, see OpenID::Consumer::CheckIDRequest#send_redirect? 
    def authenticate(*args, &block)
      options = args.last.is_a?(::Hash) ? args.pop : params
      credentials = args.first || params[:credentials] || {}
      case
        when id = extract_openid_identity(credentials)
          return_to    = options[:return_to] || root_url
          realm        = options[:realm] || root_url # Identifies this site to the user at the OpenID provider's pages.
          open_id_request = OpenID::Consumer.new(session, open_id_store).begin(id)
          open_id_request.return_to_args['open_id_complete'] = '1'
          oid_url = open_id_request.redirect_url(realm, return_to)
          redirect_to(oid_url) and return
        else
          if u = User.authenticate(credentials[:login], credentials[:password])
            @authentication_method = request.ssl? ? :https_post : :http_post
            self.current_user = u # login
            if options[:remember_me]
              u.generate_security_token
              cookies[:authentication_token] = { :value => u.security_token, :expires => u.token_expiry }
            end
            yield u if block_given?
          else
            handle_authentication_failure("Invalid UserID or password")
          end
      end
    end
    private :authenticate
    
    # Extract an OpenID identity URL from the credentials, if present.
    def extract_openid_identity(credentials)
      credentials[:login] && credentials[:login].slice(/(https?|xri):\/\/.*/) || credentials[:openid_identifier] || credentials[:openid_url]
    end
    
    def open_id_store
      defined?(OpenIdAuthentication) ? OpenIdAuthentication.store : ::OpenID::Store::Filesystem.new(RAILS_ROOT + "/tmp/openids")
    end
    
    # Identifies the authenticated user, if any.  Override/chain this method to add implicit guest 
    # or other application-specific authentication methods.
    # Ordering is very important for semantics as multiple authentication methods are sometimes active on a given request.
    # Rule 1: auth_cookie and session both (normally) rely on cookies, but auth_cookies are intended to provide long-term auth, not request-to-request
    #         auth.  So we should have session before cookie.
    def authenticated_user
      @authenticated_user ||= user_by_http_auth || user_by_token || user_by_session || user_by_authentication_cookie || user_by_openid rescue nil
    end
    alias authenticated? authenticated_user
    alias current_user authenticated_user

    # Attempt to authenticate with a URL-encoded security token.  Remove the token from the parameters if present.
    def user_by_token
      return unless params && params[:security_token]
      returning User.authenticate_by_token(params[:security_token]) do |u|
        @authentication_method = :token if u
      end
    end
    
    # Attempt to authenticate with a cookie-based security token
    def user_by_authentication_cookie
      return unless cookies[:authentication_token]
      returning User.authenticate_by_token(cookies[:authentication_token]) do |u|
        @authentication_method = :cookie if u
      end
    end
    
    # Attempt to authenticate with HTTP Auth information
    def user_by_http_auth
      returning authenticate_with_http_basic { |uid, pwd| User.authenticate(uid, pwd) } do |u|
        @authentication_method = :http_authentication if u
      end
    end
  
    # Attempt to authenticate with session data.
    def user_by_session
      return unless session && session[:user]
      returning User.find(session[:user]) do |u|
        @authentication_method = :session if u # This should never be an *initial* authentication method.        
      end
    end
    
    # Attempt to authenticate with an OpenID callback.
    def user_by_openid
      return unless params && params[:open_id_complete] # If this parameter is present, let's assume OpenID gem is installed.
      # We can't use params because it include Rails' psuedo-parameters.  And bugs in Rails' handling of path parameters
      # keys means we can't use handy methods on the request object.  So we resort to processing the params hash.
      original_parameters = params.reject { |key, value| request.path_parameters[key] }
      original_parameters.delete(:format)
      open_id_response = OpenID::Consumer.new(session, open_id_store).complete(original_parameters, request.url)
      case open_id_response.status
        when OpenID::Consumer::SUCCESS
          returning User.find_by_identity_url(open_id_response.identity_url) do |u|
            @authentication_method = :openid if u
            raise UnknownIdentityURL unless u
          end
        else # TODO: handle transient failures and setup status.
          raise InvalidOpenIDResponse, "#{open_id_response.status} (#{open_id_response.message})"
      end
    end
  end
end