module Authenticate #:nodoc:
  # Base error class for Authenticate module
  class AuthenticationError < StandardError
  end
  
  # Raised when a security token is present but no expiration date.
  class InvalidTokenExpiry < AuthenticationError
  end

  # Raised on attempts to validate a password when no hashed password (nor probably salt) exists.
  class MissingPassword < AuthenticationError
  end

  # OpenID authentication was successfull at the provider, but no user can be found with a matching identity_url
  class UnknownIdentityURL < AuthenticationError
  end
  
  # The OpenID provider has returned an invalid response.
  class InvalidOpenIDResponse < AuthenticationError
  end
end