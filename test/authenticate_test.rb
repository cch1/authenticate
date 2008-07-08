require 'test/unit'
require File.dirname(__FILE__) + '/test_helper.rb'

class AuthenticateTest < Test::Unit::TestCase
  fixtures :users

  def test_authentication_by_shared_secret
    assert_equal users(:chris), User.authenticate('cch1', 'Cruft')
    assert_nil User.authenticate('cch1', 'notatest')
    assert_nil User.authenticate('doesnotexist', 'Cruft')
  end

  def test_authentication_by_token
    u = users(:pascale)
    assert_equal u, User.authenticate_by_token(u.security_token)
    assert_nil User.authenticate_by_token("nothistoken")
  end

  def test_password_change
    assert_not_nil User.authenticate("pah1", "Rennes")
    users(:pascale).change_password("newpassword")
    users(:pascale).save
    assert_equal users(:pascale), User.authenticate("pah1", "newpassword")
    assert_nil User.authenticate("pah1", "Rennes")
    users(:pascale).change_password("apassword")
    users(:pascale).save
    assert_equal users(:pascale), User.authenticate("pah1", "apassword")
    assert_nil User.authenticate("pah1", "newpassword")
  end
  
  def test_login_collision
    u = User.new
    u.login = "cch1"
    u.change_password("anypassword")
    assert !u.save
  end

  def test_create_valid_user
    u = User.new
    u.login = "newUser"
    u.change_password("anewpassword")
    assert u.save  
  end
end
