# Load authentication libs
require 'authenticated_system'
require 'authenticated_user'
require 'authenticated_test_helper'
require 'GroupSmarts/authenticate/exceptions'
ActionController::Base.send :include, Authenticate::AuthenticatedSystem
ActiveRecord::Base.extend Authenticate::AuthenticatedUser::ClassMethods
Test::Unit::TestCase.send :include, Authenticate::AuthenticatedTestHelper
# Set default values for macro configuration
Authenticate::Configuration = {:realm => 'Authenticated Application', 
                                  :delete_delay => 240,
                                  :security_token_life => 48}