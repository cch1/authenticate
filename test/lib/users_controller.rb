Object.send(:remove_const, :UsersController)
class UsersController < ActionController::Base
  # See ActionController::RequestForgeryProtection for details
  # Uncomment the :secret if you're not using the cookie session store
  protect_from_forgery # :secret => '37bb2ff0a66c3b523831a45670a9f64b'
  
  # See ActionController::Base for details 
  # Uncomment this to filter the contents of submitted sensitive data parameters
  # from your application log (in this case, all fields with names like "password"). 
  # filter_parameter_logging :password

  prepend_before_filter :authentication
  skip_before_filter(:authentication, :only => ['login'])
  
  def new
    render :text => "new action"
  end
  
  def login
    u = User.find_by_login(params[:user][:login])
    self.current_user = u
    render :text => 'logged in'
  end
  
  def logout
    self.current_user = nil
    render :text => 'logged out'
  end
end
