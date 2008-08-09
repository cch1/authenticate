module Authenticate
  module AuthenticatedUser
    module ClassMethods
      def authenticated
        require 'digest/sha2'
        extend SingletonMethods
        include InstanceMethods
  
        attr_accessor :new_password

        validates_presence_of :login
        validates_uniqueness_of :login
        validates_confirmation_of :password, :if => :validate_password?

        protected 
        attr_reader :password
        after_validation :encrypt_password
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
        [Array.new(0.75 * salt_length){rand(256).chr}.join].pack("m").gsub(/\n/, '')[0..salt_length - 1]
      end
      
      # Hash the password and salt iteratively.  The value of iteration has apparently been questioned in the cryptographic 
      # community (see reference one below), but assumed practical in the applied art of password management (as shown in 
      # references two and three) in increasing the amount of time required to execute a dictionary attack.
      # http://www.linuxworld.com/cgi-bin/mailto/x_linux.cgi?pagetosend=/export/home/httpd/linuxworld/news/2007/111207-hash.html
      # http://macshadows.com/kb/index.php?title=Mac_OS_X_password_hashes
      # http://www.adamberent.com/documents/KeyIterations&CryptoSalts.pdf
      def encrypt(salt, password)
        hash_length = self.columns_hash['hashed_password'].limit
        key = salt + password
        # Light up the CPU
        raise "Missing configuration value" unless (Authenticate::Configuration[:hash_iterations] && (Authenticate::Configuration[:hash_iterations] > 0))
        Authenticate::Configuration[:hash_iterations].times { key = Digest::SHA512.hexdigest(key) }
        key[0..hash_length - 1]
      end
    end

    module InstanceMethods
      def initialize(*args)
        super
        @new_password = !@password.nil?
      end
  
      def password?(password)
        self.class.encrypt(self.salt, password) == self.hashed_password         
      end
      
      def valid_token?
        security_token && !self.token_expired?
      end
      
      def token_expired?
        raise Authenticate::InvalidTokenExpiry unless self.token_expiry.is_a?(Time)
        Time.now > self.token_expiry
      end
  
      def bump_token_expiry(h = nil)
        write_attribute('token_expiry', h || Authenticate::Configuration[:security_token_life].hours.from_now)
        update_without_callbacks
      end
  
      def valid_password?
        hashed_password && !(hashed_password.length == 0)
      end
      
      def generate_security_token(hours = Authenticate::Configuration[:security_token_life])
          new_security_token(hours)
      end
      alias :security_token! :generate_security_token
  
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
        @password_confirmation = confirm
      end
      
      # Change the user's password to the given password and trigger encryption to occur on validation.
      def password=(pw)
        @password = pw
        @new_password = true
      end
      
      protected  
      def validate_password?
        @new_password
      end

      def encrypt_password
        # This method should only really be called if password is valid, so check for errors to avoid writing garbage.
        if @new_password and !self.errors[:password]
          write_attribute("salt", self.class.salt)
          write_attribute("hashed_password", self.class.encrypt(self.salt, @password))
          wipe_password
        end
      end
  
      # Attempt to expunge passwords from memory and reset encryption-required flag.
      def wipe_password
        @new_password = false
        @password = nil
        @password_confirmation = @password
        true
      end
  
      # Generate a new security token valid for hours hours.  The token is Base64 encoded and stripped of newlines for URL and DB safety.
      def new_security_token(hours)
        token_length = User.columns_hash["security_token"].limit
        token = Digest::SHA512.hexdigest([Array.new(0.75 * token_length){rand(256).chr}.join].pack("m").gsub(/\n/, ''))[0..token_length - 1]
        write_attribute('security_token', token)
        write_attribute('token_expiry', hours.hours.from_now)
        update_without_callbacks
        return self.security_token
      end
    end # module
  end # module
end # module