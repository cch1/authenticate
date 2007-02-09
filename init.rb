# Load authentication libs
require "authenticated_system"
require "authenticated_user"
ActionController::Base.send(:include, Authentication::AuthenticatedSystem)
ActiveRecord::Base.extend Authentication::AuthenticatedUser::ClassMethods