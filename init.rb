# Load authentication libs
require "authenticated_system"
require "authenticated_user"
require 'authenticated_test_helper'
ActionController::Base.send :include, Authentication::AuthenticatedSystem
ActiveRecord::Base.extend Authentication::AuthenticatedUser::ClassMethods
Test::Unit::TestCase.send :include, Authentication::AuthenticatedTestHelper