module Authenticate
  module AuthenticatedUser
    module ClassMethods
      def authenticated
        require 'digest/sha2'
        extend SingletonMethods
        include InstanceMethods
  
        validates_presence_of :login
        validates_uniqueness_of :login
        validates_confirmation_of :password

        # Masking of the cleartext password happens during encryption. Encryption is configured to happen
        # after_validation -thus balancing security risks with the need to validate the cleartext password
        # Beware you do not expose the cleartext password in an unencrypted client-side session store or HTML form.
        after_validation :encrypt_password

        protected 
        attr_reader :password
        attr_accessor :pw_state
      end
    end

    module SingletonMethods
      def authenticate_by_password(login, password)
        sleep(Authenticate::Configuration[:authentication_delay].to_f)
        u = self.find_by_login(login)
        u && u.password?(password) ? u : nil
      end
      alias authenticate authenticate_by_password

      def authenticate_by_token(token)
        sleep(Authenticate::Configuration[:authentication_delay].to_f)
        u = self.find_by_security_token(token)
        u && u.valid_token? ? u : nil
      end
      
      # Generate a random Base64-encoded salt string to prevent pre-calculated dictionary attacks and collisions.  Newlines are
      # removed from the string to ensure DB compatibility (SQLite!).
      # http://phpsec.org/articles/2005/password-hashing.html
      def salt
        salt_length = self.columns_hash['salt'].limit
        [Array.new(0.75 * salt_length){rand(256).chr}.join].pack("m").gsub(/\n/, '')[0, salt_length]
      end
      
      # Hash the password and salt iteratively.  The value of iteration has apparently been questioned in the cryptographic 
      # community (see reference one below), but assumed practical in the applied art of password management (as shown in 
      # references two and three) in increasing the amount of time required to execute a dictionary attack.
      # http://www.linuxworld.com/cgi-bin/mailto/x_linux.cgi?pagetosend=/export/home/httpd/linuxworld/news/2007/111207-hash.html
      # http://macshadows.com/kb/index.php?title=Mac_OS_X_password_hashes
      # http://www.adamberent.com/documents/KeyIterations&CryptoSalts.pdf
      def encrypt(salt, password)
        return password unless password && salt
        hash_length = self.columns_hash['hashed_password'].limit
        iterated_hash_length = Authenticate::Configuration[:compatibility_mode] ? hash_length : 0
        key = salt + password
        # Light up the CPU
        raise "Missing configuration value" unless (Authenticate::Configuration[:hash_iterations] && (Authenticate::Configuration[:hash_iterations] > 0))
        Authenticate::Configuration[:hash_iterations].times { key = Digest::SHA512.hexdigest(key)[0..iterated_hash_length - 1] }
        key[0, hash_length]
      end
    end

    module InstanceMethods
      def password?(password)
        self.class.encrypt(self.salt, password) == self.hashed_password         
      end
      
      def valid_token?
        security_token && !self.token_expired?
      end
      
      def token_expired?
        raise Authenticate::InvalidTokenExpiry unless token_expiry.is_a?(Time)
        Time.now > token_expiry
      end
  
      def bump_token_expiry(h = Authenticate::Configuration[:security_token_life])
        raise "Can't bump token expiration when token has not been set." unless security_token
        returning h.hours.from_now do |t|
          self.token_expiry = t
          update_without_callbacks
        end
      end

      def generate_security_token(hours = Authenticate::Configuration[:security_token_life])
        new_security_token(hours)
      end
      alias :security_token! :generate_security_token

      # TODO: Deprecated -nothing to do with authentication.
      def set_delete_after
        h = Authenticate::Configuration[:delete_delay] * 24
        write_attribute('deleted', true)
        write_attribute('delete_after', h.hours.from_now)
        # Generate and return a token here, so that it expires at
        # the same time that the account deletion takes effect.
        return generate_security_token(h)
      end

      # Change the user's password to the given password.  As a convenience, the password_confirmation
      # virtual attribute is also set to support validations.
      # TODO: DEPRECATED 
      def change_password(pw, confirm = pw)
        self.password = pw
        self.password_confirmation = confirm
      end

      # Change the user's password to the given password and trigger encryption to occur on validation.
      # NB: Setting the password to the mask value after intially setting it to any other value will result
      # in the second password not being saved.
      def password=(pw)
        return pw if pw == @password && pw_state == :masked # Don't foul up encryped version
        returning @password = pw do |p|
          self.pw_state = :cleartext
          self.salt = nil
          self.hashed_password = nil
        end
      end
      
      # Normalize the OpenID identity URL on assignment
      def identity_url=(u)
        u = OpenID.normalize_url(u) if defined?(OpenID) rescue u # Not pretty, but OpenID raises too many exceptions.
        write_attribute(:identity_url, u)
      end

      protected
      # The password (and password_confirmation) virtual attributes can only be validated when they hold
      # cleartext.  If they have been masked, validations are not appropriate.  If they are not set (as
      # would be the case on a rehydrated record) then they should not be validated either.
      def validate_password?
        pw_state == :cleartext
      end

      # Encrypt the cleartext password and store encrypted version in database-backed attributes, then mask
      # the cleartext version of the password. If an encrypted version is already present skip the encryption.
      # It is assumed that this method is only invoked when the password is valid (as would be the case in a
      # before_save macro).
      def encrypt_password
        return unless pw_state == :cleartext
        raise AuthenticationError, "Can't overwrite existing encrypted password." unless hashed_password.nil?
        self.salt = self.class.salt
        self.hashed_password = self.class.encrypt(self.salt, password)
        mask_password
      end

      # Expunge cleartext passwords from memory after encrypted version has been created.
      # Instead of removing the password altogether, we replace it with a mask value of the
      # same length to better support HTML forms.
      def mask_password
        @password = "*" * password.length if password
        @password_confirmation = "*" * password_confirmation.length if password_confirmation
        self.pw_state = :masked
      end

      # Generate a new security token valid for hours hours.  The token is Base64 encoded and stripped of newlines for URL and DB safety.
      def new_security_token(hours)
        token_length = self.class.columns_hash["security_token"].limit
        returning Digest::SHA512.hexdigest([Array.new(0.75 * token_length){rand(256).chr}.join].pack("m").gsub(/\n/, ''))[0, token_length] do |token|
          self.security_token = token
          self.token_expiry = hours.hours.from_now
          update_without_callbacks
        end
      end
    end # module
  end # module
end # module