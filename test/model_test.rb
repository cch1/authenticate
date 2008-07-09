require File.dirname(__FILE__) + '/test_helper.rb'

class ModelTest < ActiveSupport::TestCase
  fixtures :users

  test 'should authenticate by shared secret' do
    assert_equal users(:chris), User.authenticate('cch1', 'Cruft')
    assert_nil User.authenticate('cch1', 'notatest')
    assert_nil User.authenticate('doesnotexist', 'Cruft')
  end

  test 'should authenticate by token' do
    u = users(:pascale)
    assert_equal u, User.authenticate_by_token(u.security_token)
    assert_nil User.authenticate_by_token("nothistoken")
  end

  test 'should change password' do
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
  
  test 'should not create user when there is a userid collision' do
    u = User.new
    u.login = "cch1"
    u.change_password("anypassword")
    assert !u.save
  end

  test 'should create valid user' do
    u = User.new
    u.login = "newUser"
    u.change_password("anewpassword")
    assert u.save  
  end
end
