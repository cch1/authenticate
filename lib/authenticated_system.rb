module Authenticate
  module AuthenticatedSystem
    
    protected
    # Returns the current user.  No implicit logging in occurs.
    attr_reader :current_user
    alias logged_in? current_user
    
    # Assigns the current_user, effectively performing login and logout operations.
    # TODO: Should work even if sessions are disabled.
    def current_user=(u)
      if u
        # Could regenerate token instead for nonce behavior
        cookies[:authentication_token] = { :value => u.security_token , :expires => u.bump_token_expiry } if cookies[:authentication_token] 
        session[:authentication_method] ||= (@authentication_method || :unknown) # Record authentication method used at login.
        logger.info "Authentication: User #{u.login} logged in via #{authentication_method}." unless session[:user] == u.id
        logger.debug "Authentication: User #{u.login} authenticated via #{@authentication_method}."
      else # remove persistence
        cookies.delete :authentication_token
        session[:authentication_method] = nil
        logger.info "Authentication: User #{current_user.login} logged out." if current_user
      end
      @current_user = u
      session[:user] = u && u.id
      User.current = u # This is a nasty coupling that should be eliminated...
    end
    
    # Returns the method used to authenticate the current user
    def authentication_method
      returning @authentication_method do |m|
        logger.warn "Authentication: Unknown authentication method." unless m        
      end
    end
    
    # Checks for an authenticated user, implicitly logging him in if present.
    # Authentication Filter.  Usage:
    #   prepend_before_filter :authentication, :only => [:actionx, :actiony]
    #   skip_before_filter :authentication, :only => [:actionx]
    # TODO: This should be an around filter, and authentication state should be cleared everywhere but the session after each request.
    def authentication
      returning self.authenticated_user do |u|
        self.current_user = u # this is the login
        handle_authentication_failure unless u
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
    # When the user is authenticated, the associated block is executed.  This is a high-level construct, and as such it takes care 
    # of login, logging, session storage for authentication on subsequent requests, and even setting the authentication cookie.  But
    # it also depends on specific named parameters, such as the credentials parameters and the remember_me 
    # TODO: The callback from the provider will be an HTTP GET.  To add support for POST, see OpenID::Consumer::CheckIDRequest#send_redirect? 
    def authenticate(*args, &block)
      options = args.last.is_a?(::Hash) ? args.pop : params
      credentials = args.first || params[:credentials]
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
            @authentication_method = :post
            self.current_user = u # login
            cookies[:authentication_token] = { :value => u.generate_security_token, :expires => u.token_expiry } if options[:remember_me]
            yield u if block_given?
          else
            handle_authentication_failure("Invalid UserID or password")
          end
      end
    end
    private :authenticate
    
    # Extract an OpenID identity URL from the credentials, if present.
    def extract_openid_identity(credentials)
      credentials[:login] && credentials[:login].slice(/http:\/\/.*/) || credentials[:openid_identifier] || credentials[:openid_url]
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
      user_by_http_auth || user_by_token || user_by_session || user_by_authentication_cookie || user_by_openid
    end

    # Attempt to authenticate with a URL-encoded security token.  Remove the token from the parameters if present.
    def user_by_token
      return unless p = params.delete(:security_token)
      returning User.authenticate_by_token(p) do |u|
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
      return unless session[:user]
      returning User.find(session[:user]) do |u|
        @authentication_method = :session if u # This should never be an *initial* authentication method.        
      end
    end
    
    # Attempt to authenticate with an OpenID callback.
    def user_by_openid
      return unless params[:open_id_complete] # If this parameter is present, let's assume OpenID gem is installed.
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