require File.dirname(__FILE__) + '/test_helper.rb'

class ModelTest < ActiveSupport::TestCase
  fixtures :users

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
    token = u.security_token!
    assert_equal u, User.authenticate_by_token(u.security_token)
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

  def test_should_change_password
    u = users(:pascale)
    u.password = "Lyon"
    assert u.save
    assert_equal u, User.authenticate(u.login, "Lyon") # is the new one valid?
    assert_nil User.authenticate(u.login, "Rennes") # is the old one invalid?
  end
  
  def test_should_not_change_password_with_bad_confirmation_with_old_API
    users(:pascale).change_password("anewpassword", "bnewpassword")
    assert !users(:pascale).save
    assert User.authenticate("pah1", "Rennes")
  end
  
  def test_should_not_change_password_with_bad_confirmation
    users(:pascale).password = "anewpassword"
    users(:pascale).password_confirmation = "bnewpassword"
    assert !users(:pascale).save
    assert User.authenticate("pah1", "Rennes")
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
    assert u.save  
  end
  
  # Test the ability to create a user and set the password in one step.
  def test_should_create_user_with_password
    u = User.new({:login => 'newUser', :password => "x"})
    assert u.new_password
    assert u.save
    assert u.password?('x')
  end
  
  # Test nil passwords.  To disable nil passwords, use a database restriction
  # or a custom validation that examines the @password virtual attribute.
  def test_should_create_user_with_nil_password
    u = User.new({:login => 'newUser'})
    assert !u.new_password
    assert u.save  
  end

  # Test blank passwords.  To disable blank passwords use
  # validates_presence_of :password, :if => :validate_password?
  def test_should_create_user_with_blank_password
    u = User.new({:login => 'newUser', :password => ''})
    assert u.new_password
    assert u.save
    assert u.password?('')
  end
end