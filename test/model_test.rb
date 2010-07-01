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

  def test_authenticate_by_shared_secret
    assert_equal users(:chris), User.authenticate('cch1', 'Cruft')
  end

  def test_not_authenticate_with_invalid_shared_secret
    assert_nil User.authenticate('cch1', 'notatest')
    assert_nil User.authenticate('doesnotexist', 'Cruft')
  end

  def test_authenticate_by_token
    u = users(:pascale)
    assert_equal u, User.authenticate_by_token(u.security_token)
  end

  def test_generate_valid_token
    u = users(:pascale)
    t = u.security_token!
    assert_equal u, User.authenticate_by_token(t)
  end

  def test_not_authenticate_with_invalid_token
    assert_nil User.authenticate_by_token("invalidtoken")
  end

  def test_change_password_with_old_API
    u = users(:pascale)
    assert_not_nil User.authenticate(u.login, "Rennes")
    u.change_password("newpassword")
    assert u.save
    assert_equal u, User.authenticate(u.login, "newpassword") # is the new one valid?
    assert_nil User.authenticate(u.login, "Rennes") # is the old one invalid?
  end

  def test_persist_changed_password
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

  def test_allow_validating_presence_of_password
    @picky_user.instance_eval do
      validates_presence_of :password
    end
    # Invalid due to nil
    u = @picky_user.new(:login => 'me', :password => nil)
    assert !u.valid?
    assert u.errors[:password]
    # Invalid due to blank
    u = @picky_user.new(:login => 'me', :password => '')
    assert !u.valid?
    assert u.errors[:password]
    # Valid
    u = @picky_user.new(:login => 'me', :password => 'Something')
    assert u.valid?
    u.save
    assert u.valid?
  end

  def test_allow_validating_confirmation_of_password
    @picky_user.instance_eval do
      validates_confirmation_of :password
    end
    u = @picky_user.new(:login => 'me', :password => 'apassword', :password_confirmation => 'bpassword')
    assert !u.valid?
    assert u.errors[:password]
    u = @picky_user.new(:login => 'metoo', :password => 'apassword', :password_confirmation => 'apassword')
    assert u.valid?
  end

  def test_map_validations
    pw = "Valid"
    @picky_user.instance_eval do
      validates_each :password do |record, attr, value|
        record.errors.add(attr) unless value == pw
      end
    end
    u = @picky_user.new(:login => 'me', :password => pw.reverse, :password_confirmation => pw.reverse)
    assert !u.valid?
    assert u.errors[:password]
    u = @picky_user.new(:login => 'me', :password => pw, :password_confirmation => pw)
    assert u.save
    assert u.valid?
  end

  def test_not_create_user_when_there_is_a_userid_collision
    u = User.new({:login => 'cch1'})
    assert !u.save
  end

  def test_not_create_user_without_userid
    u = User.new
    assert !u.save
    assert u.errors[:login]
  end

  # Test creation of a user with minimal information.
  def test_create_valid_user
    u = User.new({:login => 'newUser'})
    assert u.valid?
  end

  # Test the ability to create a user and set the password in one step.
  def test_create_user_with_password
    u = User.new({:login => 'newUser', :password => "x"})
    assert u.password?('x')
    assert u.save
    assert u.password?('x')
  end

  # Test nil passwords.
  def test_create_user_with_nil_password
    u = User.new({:login => 'newUser'})
    assert u.password?(nil)
    assert u.save
    assert u.password?(nil)
  end

  def test_clear_password
    u = users(:chris)
    assert !u.password?(nil)
    u.clear_password!
    assert u.password?(nil)
    assert u.save
    assert u.password?(nil)
  end

  # Test blank passwords.
  # This test exposes situations where the empty string is a sentinel value
  def test_blank_password
    u = users(:chris)
    assert !u.password?('')
    u.password = ''
    assert u.password?('')
    assert u.save
    assert u.password?('')
  end

  # The OpenID identity URL should be normalized on assignment.
  def test_set_identity_url
    assert users(:pascale).identity_url = 'http://pascale.oid.com'
    assert_equal 'http://pascale.oid.com/', users(:pascale).identity_url
  end

  def test_unset_identity_url
    assert_nothing_raised do
      assert_nil users(:pascale).identity_url = nil
    end
    assert_nil users(:pascale).identity_url
  end

  def test_bump_token_expiry
    assert_kind_of Time, users(:pascale).bump_token_expiry(96)
    assert_in_delta 96.hours.from_now, users(:pascale).token_expiry, 1
  end

  def test_bump_token_expiry_by_configured_default
    assert_kind_of Time, users(:pascale).bump_token_expiry
    assert_in_delta Authenticate::Configuration[:security_token_life].hours.from_now, users(:pascale).token_expiry, 1
  end

  # Obfuscate the cleartext password immediately with a value that "looks" right in HTML forms.
  def test_obfuscate_password_on_set
    pw = 'newPassword'
    u = User.new({:login => 'newUser', :password => pw, :password_confirmation => pw})
    assert_not_equal pw, u.password
    assert_not_nil u.password
  end

  # Obfuscate the cleartext password_confirmation immediately with a value that "looks" right in HTML forms.
  def test_obfuscate_password_confirmation_on_set
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
  def test_retain_password_when_set_to_obfuscated_version
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

  # This test exposes situations where a sentinel value is NOT used to a represent password that has
  # been set but is un-knowable.  A sentinel allows round-trip preservation of un-knowable passwords,
  # and comprehensive round-trip preservation is not possible without a sentinel value.  An unprintable
  # sentinel requires a special interpretation of nil or the empty string -either or both of which may
  # have more standard or application-specific usage.  A printable sentinel introduces visible artifacts
  # in form processing -exactly where round-trip preservation is useful in the first place.
  # TODO: consider a sentinel value that is very long -it's perhaps a reasonable visual presentation
  # and would restore round-trip processing while preserving nil/empty passwords.
  def test_round_trip
    assert u = User.create({:login => 'newUser', :password => 'aPassword'})
    assert !u.changed? # Password is no longer knowable.
    u.password = u.password
    assert !u.changed?
  end

  def test_false_update_is_not_dirty
    pw = 'aPassword'
    assert u = User.create({:login => 'newUser', :password => pw})
    u.password = pw
    assert !u.changed?
  end
end