require File.dirname(__FILE__) + '/test_helper.rb'

class ModelTest < ActiveSupport::TestCase
  fixtures :users

  test 'should authenticate by shared secret' do
    assert_equal users(:chris), User.authenticate('cch1', 'Cruft')
  end

  test 'should not authenticate with invalid shared secret' do
    assert_nil User.authenticate('cch1', 'notatest')
    assert_nil User.authenticate('doesnotexist', 'Cruft')
  end

  test 'should authenticate by token' do
    u = users(:pascale)
    assert_equal u, User.authenticate_by_token(u.security_token)
  end
  
  test 'should generate valid token' do
    u = users(:pascale)
    token = u.security_token!
    assert_equal u, User.authenticate_by_token(u.security_token)
  end

  test 'should not authenticate with invalid token' do
    assert_nil User.authenticate_by_token("invalidtoken")
  end
  
  test 'should change password with old API' do
    u = users(:pascale)
    assert_not_nil User.authenticate(u.login, "Rennes")
    u.change_password("newpassword")
    assert u.save
    assert_equal u, User.authenticate(u.login, "newpassword") # is the new one valid?
    assert_nil User.authenticate(u.login, "Rennes") # is the old one invalid?
  end

  test 'should change password' do
    u = users(:pascale)
    u.password = "Lyon"
    assert u.save
    assert_equal u, User.authenticate(u.login, "Lyon") # is the new one valid?
    assert_nil User.authenticate(u.login, "Rennes") # is the old one invalid?
  end
  
  test 'should not change password with bad confirmation with old API' do
    users(:pascale).change_password("anewpassword", "bnewpassword")
    assert !users(:pascale).save
    assert User.authenticate("pah1", "Rennes")
  end
  
  test 'should not change password with bad confirmation' do
    users(:pascale).password = "anewpassword"
    users(:pascale).password_confirmation = "bnewpassword"
    assert !users(:pascale).save
    assert User.authenticate("pah1", "Rennes")
  end
  
  test 'should not create user when there is a userid collision' do
    u = User.new({:login => 'cch1'})
    assert !u.save
  end

  test 'should not create user without userid' do
    u = User.new
    assert !u.save
    assert u.errors[:login]
  end

  # Test creation of a user with minimal information.
  test 'should create valid user' do
    u = User.new({:login => 'newUser'})
    assert u.save  
  end
  
  # Test the ability to create a user and set the password in one step.
  test 'should create user with password' do
    u = User.new({:login => 'newUser', :password => "x"})
    assert u.new_password
    assert u.save
    assert u.password?('x')
  end
  
  # Test nil passwords.  To disable nil passwords, use a database restriction
  # or a custom validation that examines the @password virtual attribute.
  test 'should create user with nil password' do
    u = User.new({:login => 'newUser'})
    assert !u.new_password
    assert u.save  
  end

  # Test blank passwords.  To disable blank passwords use
  # validates_presence_of :password, :if => :validate_password?
  test 'should create user with blank password' do
    u = User.new({:login => 'newUser', :password => ''})
    assert u.new_password
    assert u.save
    assert u.password?('')
  end
end
