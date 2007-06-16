module Authenticate
  module AuthenticatedSystem
    
    protected
    # Returns the current user.  No implicit logging in occurs.
    def current_user
      @current_user
    end
    alias logged_in? current_user
    
    # Assigns the current_user, effectively performing login and logout operations.
    def current_user=(u)
      @current_user = u
      User.current = u
      if u
        session[:user] = u.id
        session[:authentication_method] ||= @authentication_method
      else # remove persistence
        cookies.delete :authentication_token
        session[:user] = nil
        session[:authentication_method] = nil
      end
    end
    
    # Checks for an authenticated user, implicitly logging him in if present.
    # Authentication Filter.  Usage:
    #   before_filter :authentication, :only => [:actionx, :actiony]
    #   skip_before_filter :authentication, :only => [:actionx]
    def authentication
      self.current_user = self.authenticated_user # this is the login
      return true if logged_in?
      access_denied
      false
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

    # Allows current_user and logged_in? to be used in views.    
    def self.included(base)
      ActionController::Base.send :helper_method, :current_user, :logged_in?
      if base.respond_to?(:rescue_responses)
        base.rescue_responses['Authenticate::AuthenticationError'] = :unauthorized # Poorly named -it really is intended for 'unauthenticated'.
      end
    end
    
    # Identifies the authenticated user, if any.
    def authenticated_user
      u = user_by_session_cookie || user_by_authentication_cookie || user_by_http_auth || user_by_token
      @authentication_method = nil unless u
      u
    end

    # Attempt to authenticate with a URL-encoded security token
    def user_by_token
      @authentication_method = :token
      User.authenticate_by_token(params[:security_token])
    end
    
    # Attempt to authenticate with a cookie-based security token
    def user_by_authentication_cookie
      @authentication_method = :cookie
      if (user = User.authenticate_by_token(cookies[:authentication_token]))
        user.bump_token_expiry # Could regenerate token instead for nonce behavior
        cookies[:authentication_token] = { :value => user.security_token , :expires => user.token_expiry }
      end
      return user
    end
    
    # Attempt to authenticate with HTTP Auth information
    def user_by_http_auth
      @authentication_method = :http_authentication
      user, password = get_http_auth_data
      if user
        User.authenticate(user, password)
      end
    end
  
    # Attempt to authenticate with session cookie
    def user_by_session_cookie
      @authentication_method = :session # This should never be an *initial* authentication method.
      session[:user] && User.find(session[:user])
    end
  
    private
    @@http_auth_headers = %w(X-HTTP_AUTHORIZATION HTTP_AUTHORIZATION Authorization)
    # gets HTTP Authentication info
    def get_http_auth_data
      auth_key  = @@http_auth_headers.detect { |h| request.env.has_key?(h) }
      auth_data = request.env[auth_key].to_s.split unless auth_key.blank?
      return auth_data && auth_data[0] == 'Basic' ? Base64.decode64(auth_data[1]).split(':')[0..1] : [nil, nil] 
    end
    
  end
end