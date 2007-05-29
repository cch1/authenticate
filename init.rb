# Load authentication libs
require 'authenticated_system'
require 'authenticated_user'
require 'authenticated_test_helper'
require 'exceptions'
ActionController::Base.send :include, Authenticate::AuthenticatedSystem
ActiveRecord::Base.extend Authenticate::AuthenticatedUser::ClassMethods
Test::Unit::TestCase.send :include, Authenticate::AuthenticatedTestHelper