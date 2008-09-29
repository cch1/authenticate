# Load authentication libs
require 'authenticated_system'
require 'authenticated_user'
require 'authenticated_test_helper'
require 'GroupSmarts/authenticate/exceptions'
begin
  require 'openid'
  require 'openid/store/filesystem'
rescue LoadError
  RAILS_DEFAULT_LOGGER.warn("Could not load libraries for OpenID support.")
end
ActionController::Base.send :include, Authenticate::AuthenticatedSystem
ActiveRecord::Base.extend Authenticate::AuthenticatedUser::ClassMethods
Test::Unit::TestCase.send :include, Authenticate::AuthenticatedTestHelper
# Set default values for macro configuration
Authenticate::Configuration = {:realm => 'Authenticated Application', 
                                  :delete_delay => 240,
                                  :security_token_life => 48,
                                  :hash_iterations => 50000,
                                  :authentication_delay => 0.5.seconds}