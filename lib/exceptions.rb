module Authenticate #:nodoc:

  # Base error class for Authorization module
  class AuthenticationError < StandardError
  end
  
  # Raised when a security token is present but no expiration date.
  class InvalidTokenExpiry < AuthenticationError
  end
  
end