Object.send(:remove_const, :User)
class User < ActiveRecord::Base
  authenticated
  cattr_accessor :current # Class attribute automatically set after authentication
end