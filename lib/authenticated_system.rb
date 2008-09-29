module Authenticate
  module AuthenticatedSystem
    
    protected
    # Returns the current user.  No implicit logging in occurs.
    def current_user
      @current_user
    end
    alias logged_in? current_user
    
    # Assigns the current_user, effectively performing login and logout operations.
    # TODO: Should work even if sessions are disabled.
    def current_user=(u)
      if u
        if cookies[:authentication_token]
          u.bump_token_expiry # Could regenerate token instead for nonce behavior
          cookies[:authentication_token] = { :value => u.security_token , :expires => u.token_expiry }
        end
        session[:authentication_method] ||= (@authentication_method || :unknown) # Record authentication method used at login.
        session[:user] = u.id
        logger.info "Authentication: User #{u.login} logged in via #{session[:authentication_method]} and authenticated via #{@authentication_method}."
      else # remove persistence
        cookies.delete :authentication_token
        session[:user] = nil
        session[:authentication_method] = nil
        logger.info "Authentication: User #{@current_user} logged out."
      end
      @current_user = u
      User.current = u # This is a nasty coupling that should be eliminated...
    end
    
    # Checks for an authenticated user, implicitly logging him in if present.
    # Authentication Filter.  Usage:
    #   prepend_before_filter :authentication, :only => [:actionx, :actiony]
    #   skip_before_filter :authentication, :only => [:actionx]
    # TODO: This should be an around filter, and authentication state should be cleared everywhere but the session after each request.
    def authentication
      returning self.authenticated_user do |u|
        self.current_user = u # this is the login
        access_denied unless u
      end
    end

    # Manage response to authentication failure.  Override this method in application.rb.
    def access_denied(message = nil)
      raise Authenticate::AuthenticationError, message
    end
  
    # Store current URI in the session.
    # We can return to this location by calling return_location
    def store_location
      session[:return_to] = request.request_uri
    end

    # move to the last store_location call or to the passed default one
    def redirect_to_stored_or_default(default=nil)
      if session[:return_to].nil?
        redirect_to default
      else
        redirect_to session[:return_to]
        session[:return_to] = nil
      end
    end

    def redirect_back_or_default(default=nil)
      if request.env["HTTP_REFERER"].nil?
        redirect_to default
      else
        redirect_to :back
      end
    end

    # Allows current_user and logged_in? to be used in views.  Also sets up a rescue response where supported.
    def self.included(base)
      ActionController::Base.send :helper_method, :current_user, :logged_in?
      if base.respond_to?(:rescue_responses)
        base.rescue_responses['Authenticate::AuthenticationError'] = :unauthorized # Poorly named -it really is intended for 'unauthenticated'.
      end
    end
    
    # Authenticate the user based on provided credentials.  Credentials object can include userid, password and OpenID URLs.
    # When the user is authenticated, the associated block is executed.  This is a high-level construct, and as such it takes care 
    # of login, logging, session storage for authentication on subsequent requests, and even setting the authentication cookie.
    # TODO: The callback from the provider will be an HTTP GET.  To add support for POST, see OpenID::Consumer::CheckIDRequest#send_redirect? 
    def authenticate(options = {}, &block)
      credentials = options.delete(:credentials) || params[:credentials] || params[:user] || params
      case
        when id = identity_url(credentials)
          return_to    = options.delete(:return_to) || root_url
          realm        = options.delete(:realm) || root_url # Identifies this site to the user at the OpenID provider's pages.
          open_id_request = OpenID::Consumer.new(session, open_id_store).begin(id)
          open_id_request.return_to_args['open_id_complete'] = '1'
          oid_url = open_id_request.redirect_url(realm, return_to)
          redirect_to(oid_url) and return
        else
          if u = User.authenticate(credentials[:login], credentials[:password])
            # TODO: perform login actions here. 
            yield u
          else
            access_denied("Invalid UserID or password")
          end
      end
    end
    private :authenticate
    
    # Extract an OpenID identity URL from the credentials, if present.
    def identity_url(credentials)
      credentials[:login] && credentials[:login].slice(/http:\/\/.*/) || credentials[:openid_identifier] || credentials[:openid_url]
    end
    
    def open_id_store
      defined?(OpenIdAuthentication) ? OpenIdAuthentication.store : ::OpenID::Store::Filesystem.new(RAILS_ROOT + "/tmp/openids")
    end
    
    # Identifies the authenticated user, if any.  Override/chain this method to add implicit guest 
    # or other application-specific authentication methods.
    def authenticated_user
      user_by_authentication_cookie || user_by_http_auth || user_by_token || user_by_session || user_by_openid
    end

    # Attempt to authenticate with a URL-encoded security token.  Remove the token from the parameters if present.
    def user_by_token
      return unless p = params.delete(:security_token)
      if (user = User.authenticate_by_token(p))
        @authentication_method = :token
      end
      user
    end
    
    # Attempt to authenticate with a cookie-based security token
    def user_by_authentication_cookie
      return unless cookies[:authentication_token]
      if (user = User.authenticate_by_token(cookies[:authentication_token]))
        @authentication_method = :cookie
      end
      user
    end
    
    # Attempt to authenticate with HTTP Auth information
    def user_by_http_auth
      if user = authenticate_with_http_basic { |uid, pwd| User.authenticate(uid, pwd) }
        @authentication_method = :http_authentication
      end
      user
    end
  
    # Attempt to authenticate with session data.
    def user_by_session
      return unless session[:user]
      if (user = User.find(session[:user]))
        @authentication_method = :session # This should never be an *initial* authentication method.        
      end
      user
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
          if user = User.find_by_identity_url(open_id_response.identity_url)
            @authentication_method = :openid
          else
            access_denied("Unknown identity (#{open_id_response.identity_url}).")
          end
        else
          access_denied("#{open_id_response.status} (#{open_id_response.message})")
      end
      user
    end
  end
end