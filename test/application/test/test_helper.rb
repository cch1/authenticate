ENV['RAILS_ENV'] ||= 'test'
require File.expand_path(File.dirname(__FILE__) + "/../config/environment")
require 'test_help'

# From this point forward, we can assume that we have booted a generic Rails environment plus
# our (booted) plugin.
load(File.dirname(__FILE__) + "/../db/schema.rb")

# Run the migrations (optional)
# ActiveRecord::Migrator.migrate("#{Rails.root}/db/migrate")

# Set Test::Unit options for optimal performance/fidelity.
class ActiveSupport::TestCase
  include Authenticate::AuthenticatedTestHelper
  self.use_transactional_fixtures = true
  self.use_instantiated_fixtures  = false
  
  def self.uses_mocha(description)
    require 'mocha'
    yield
  rescue LoadError
    $stderr.puts "Skipping #{description} tests. `gem install mocha` and try again."
  end
end

# Change the encryption parameters (but not the process) to speed up tests
Authenticate::Configuration.merge!({:hash_iterations => 2, :authentication_delay => 0.01.seconds})