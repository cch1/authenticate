class UsersController < ActionController::Base
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
