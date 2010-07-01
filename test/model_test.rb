require File.expand_path(File.dirname(__FILE__) + "/application/test/test_helper.rb")

class ModelTest < ActiveSupport::TestCase
  fixtures :users

  def setup
    @picky_user = Class.new(ActiveRecord::Base) do
      set_table_name 'users'
      def self.name; "PickyUser"; end
      authenticated
    end
  end

  def test_should_authenticate_by_shared_secret
    assert_equal users(:chris), User.authenticate('cch1', 'Cruft')
  end

  def test_should_not_authenticate_with_invalid_shared_secret
    assert_nil User.authenticate('cch1', 'notatest')
    assert_nil User.authenticate('doesnotexist', 'Cruft')
  end

  def test_should_authenticate_by_token
    u = users(:pascale)
    assert_equal u, User.authenticate_by_token(u.security_token)
  end

  def test_should_generate_valid_token
    u = users(:pascale)
    t = u.security_token!
    assert_equal u, User.authenticate_by_token(t)
  end

  def test_should_not_authenticate_with_invalid_token
    assert_nil User.authenticate_by_token("invalidtoken")
  end

  def test_should_change_password_with_old_API
    u = users(:pascale)
    assert_not_nil User.authenticate(u.login, "Rennes")
    u.change_password("newpassword")
    assert u.save
    assert_equal u, User.authenticate(u.login, "newpassword") # is the new one valid?
    assert_nil User.authenticate(u.login, "Rennes") # is the old one invalid?
  end

  def test_should_persist_changed_password
    u = users(:pascale)
    u.password = "Lyon"
    assert u.save
    assert_equal u, User.authenticate(u.login, "Lyon") # is the new one valid?
    assert_nil User.authenticate(u.login, "Rennes") # is the old one invalid?
  end

  def test_validation_preserves_state
    @picky_user.instance_eval do
      validates_confirmation_of :password
    end
    u = @picky_user.new(:login => 'me', :password => 'apassword', :password_confirmation => 'bpassword')
    assert !u.valid?
    assert !u.valid?
  end

  def test_should_allow_validating_presence_of_password_against_nil_password
    @picky_user.instance_eval do
      validates_presence_of :password, :on => :create
    end
    u = @picky_user.new(:login => 'me', :password => nil)
    assert !u.valid?
    assert u.errors[:password]
  end

  def test_should_allow_validating_presence_of_password_against_blank_password
    @picky_user.instance_eval do
      validates_presence_of :password, :on => :create
    end
    u = @picky_user.new(:login => 'me', :password => '')
    assert !u.valid?
    assert u.errors[:password]
  end

  def test_should_allow_validating_confirmation_of_password
    @picky_user.instance_eval do
      validates_confirmation_of :password
    end
    u = @picky_user.new(:login => 'me', :password => 'apassword', :password_confirmation => 'bpassword')
    assert !u.valid?
    assert u.errors[:password]
    u = @picky_user.new(:login => 'metoo', :password => 'apassword', :password_confirmation => 'apassword')
    assert u.valid?
  end

  def test_should_map_validations
    pw = "TheOne"
    tc = self
    @picky_user.instance_eval do
      validates_each :password do |record, attr, value|
        tc.assert_equal pw, value
        record.errors.add(attr, :confirmation, :default => "No, I am")
      end
    end
    u = @picky_user.new(:login => 'me', :password => pw, :password_confirmation => pw)
    assert !u.valid?
    assert u.errors[:password]
  end

  def test_should_not_create_user_when_there_is_a_userid_collision
    u = User.new({:login => 'cch1'})
    assert !u.save
  end

  def test_should_not_create_user_without_userid
    u = User.new
    assert !u.save
    assert u.errors[:login]
  end

  # Test creation of a user with minimal information.
  def test_should_create_valid_user
    u = User.new({:login => 'newUser'})
    assert u.valid?
  end

  # Test the ability to create a user and set the password in one step.
  def test_should_create_user_with_password
    u = User.new({:login => 'newUser', :password => "x"})
    assert u.password?('x')
    assert u.save
    assert u.password?('x')
  end

  # Test nil passwords.  To disable nil passwords, use a database restriction
  # or a custom validation that examines the password virtual attribute on create.
  def test_should_create_user_with_nil_password
    u = User.new({:login => 'newUser'})
    assert u.password?(nil)
    assert u.save
    assert u.password?(nil)
  end

  # Test blank passwords.  To disable blank passwords use
  # validates_presence_of :password, :if => :validate_password?
  def test_clear_password
    u = users(:chris)
    assert !u.password?(nil)
    u.clear_password!
    assert u.password?(nil)
    assert u.save
    assert u.password?(nil)
  end

  def test_should_create_user_with_blank_password
    u = User.new({:login => 'newUser', :password => ''})
    assert u.password?('')
    assert u.save
    assert u.password?('')
  end

  # The OpenID identity URL should be normalized on assignment.
  def test_should_set_identity_url
    assert users(:pascale).identity_url = 'http://pascale.oid.com'
    assert_equal 'http://pascale.oid.com/', users(:pascale).identity_url
  end

  def test_should_unset_identity_url
    assert_nothing_raised do
      assert_nil users(:pascale).identity_url = nil
    end
    assert_nil users(:pascale).identity_url
  end

  def test_should_bump_token_expiry
    assert_kind_of Time, users(:pascale).bump_token_expiry(96)
    assert_in_delta 96.hours.from_now, users(:pascale).token_expiry, 1
  end

  def test_should_bump_token_expiry_by_configured_default
    assert_kind_of Time, users(:pascale).bump_token_expiry
    assert_in_delta Authenticate::Configuration[:security_token_life].hours.from_now, users(:pascale).token_expiry, 1
  end

  # Obfuscate the cleartext password immediately with a value that "looks" right in HTML forms.
  def test_should_obfuscate_password_on_set
    pw = 'newPassword'
    u = User.new({:login => 'newUser', :password => pw, :password_confirmation => pw})
    assert_not_equal pw, u.password
    assert_not_nil u.password
  end

  # Obfuscate the cleartext password_confirmation immediately with a value that "looks" right in HTML forms.
  def test_should_obfuscate_password_confirmation_on_set
    @picky_user.instance_eval do
      validates_confirmation_of :password
    end
    pw = 'newPassword'
    u = @picky_user.new({:login => 'newUser', :password => pw, :password_confirmation => pw})
    assert_not_equal pw, u.password_confirmation
    assert_not_nil u.password_confirmation
  end

  # Setting the password to the current value of the virtual attribute (including the mask) should not
  # cause the encrypted password to change.
  def test_should_retain_password_when_set_to_obfuscated_version
    pw = 'aPassword'
    u = User.new({:login => 'newUser', :password => pw})
    u.password = u.password
    assert u.password?(pw)
  end

  def test_hashability
    h = Hash.new
    assert_nothing_raised do
      h[User] = true
    end
  end

  def test_round_trip
    assert u = User.create({:login => 'newUser', :password => 'aPassword'})
    u.password = u.password
    assert !u.changed?
  end
end