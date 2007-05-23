module Authentication
  module AuthenticatedSystem
    
    protected
    # Returns the current user
    def current_user
      return @current_user if @current_user
      self.current_user = user_by_session_cookie || user_by_authentication_cookie || user_by_http_auth || user_by_token
    end
    alias logged_in? current_user

    # Allows current_user and logged_in? to be used in views.    
    def self.included(base)
      ActionController::Base.send :helper_method, :current_user, :logged_in?
    end
    
    def current_user=(u)
      @current_user = u
      User.current = u
      if u
        session[:user] = u.id
      else
        session[:user] = u
      end
    end
    
    # Authentication Filter.  Usage:
    #   before_filter :authentication, :only => [:actionx, :actiony]
    #   skip_before_filter :authentication, :only => [:actionx]
    #   etc.
    def authentication
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

    # Attempt to authenticate with a URL-encoded security token
    def user_by_token
      User.authenticate_by_token(params[:security_token])
    end
    
    # Attempt to authenticate with a cookie-based security token
    def user_by_authentication_cookie
      if (user = User.authenticate_by_token(cookies[:authentication_token]))
        user.bump_token_expiry # Could regenerate token instead for nonce behavior
        cookies[:authentication_token] = { :value => user.security_token , :expires => user.token_expiry }
      end
      return user
    end
    
    # Attempt to authenticate with HTTP Auth information
    def user_by_http_auth
      user, password = get_http_auth_data
      if user
        User.authenticate(user, password)
      end
    end
  
    # Attempt to authenticate with session cookie
    def user_by_session_cookie
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