# Load authentication libs
require 'authenticate/exceptions'

begin
  require 'openid'
  require 'openid/store/filesystem'
rescue LoadError
  RAILS_DEFAULT_LOGGER.warn("Could not load libraries for OpenID support.")
end
ActionController::Base.send :include, Authenticate::AuthenticatedSystem
ActiveRecord::Base.extend Authenticate::AuthenticatedUser::ClassMethods
# Set default values for macro configuration
Authenticate::Configuration = {:realm => 'Authenticated Application', 
                                  :delete_delay => 240,
                                  :security_token_life => 48,
                                  :hash_iterations => 50000,
                                  :authentication_delay => 0.5.seconds}