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

    # Manage response to authentication failure.  Override this method
    # in your application.rb controller.
    def access_denied
      raise Authenticate::AuthenticationError
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
    
    # Identifies the authenticated user, if any.  Override/chain this method to add implicit guest 
    # or other application-specific authentication methods.
    def authenticated_user
      user_by_session || user_by_authentication_cookie || user_by_http_auth || user_by_token
    end

    # Attempt to authenticate with a URL-encoded security token
    def user_by_token
      return unless params[:security_token]
      if (user = User.authenticate_by_token(params[:security_token]))
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
  end
end