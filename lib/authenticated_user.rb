module Authentication
  module AuthenticatedUser

    def self.salt
      [Array.new(30){rand(256).chr}.join].pack("m").chomp
    end
    
    def self.encrypt(salt, password)
      key = salt + password
      # Light up the CPU
      50000.times { key = Digest::SHA512.hexdigest(key)[0..39] }
      key
    end

    module ClassMethods
      def authenticated
        require 'digest/sha2'
        extend SingletonMethods
        include InstanceMethods
  
        attr_accessor :new_password

        protected 
        attr_accessor :password, :password_confirmation
        after_save :falsify_new_password
        after_validation :crypt_password
      end
    end

    module SingletonMethods
      def authenticate_by_password(login, password)
        u = self.find_by_login(login)
        u && u.password?(password) ? u : nil
      end
      alias authenticate authenticate_by_password

      def authenticate_by_token(token)
        sleep(1)
        u = self.find_by_security_token(token)
        u && u.valid_token? ? u : nil
      end      
    end

    module InstanceMethods
      def initialize(*args)
        super
        @new_password = false
      end
  
      def password?(password)
        AuthenticatedUser.encrypt(self.salt, password) == self.hashed_password         
      end
      
      def valid_token?
        security_token && !self.token_expired?
      end
      
      def token_expired?
        raise Authenticate::InvalidTokenExpiry unless self.token_expiry.is_a?(Time)
        Time.now > self.token_expiry
      end
  
      def bump_token_expiry(h = nil)
        write_attribute('token_expiry', h || Authentication::Configuration[:security_token_life].hours.from_now)
        update_without_callbacks
      end
  
      def valid_password?
        hashed_password && !(hashed_password.length == 0)
      end
      
      def generate_security_token(hours = nil)
          new_security_token(hours)
      end
  
      def set_delete_after
        h = Authentication::Configuration[:delete_delay] * 24
        write_attribute('deleted', true)
        write_attribute('delete_after', h.hours.from_now)
  
        # Generate and return a token here, so that it expires at
        # the same time that the account deletion takes effect.
        return generate_security_token(h)
      end
  
      def change_password(pass, confirm = nil)
        self.password = pass
        self.password_confirmation = confirm.nil? ? pass : confirm
        @new_password = true
      end
      
      protected  
      def validate_password?
        @new_password
      end

      def crypt_password
        # This method should only really be called if password is valid, so check for errors to avoid writing garbage.
        if @new_password and !self.errors[:password]
          write_attribute("salt", AuthenticatedUser.salt)
          write_attribute("hashed_password", AuthenticatedUser.encrypt(salt, @password))
        end
      end
  
      def falsify_new_password
        @new_password = false
        true
      end
  
      def new_security_token(hours = nil)
        write_attribute('security_token', Digest::SHA512.hexdigest([Array.new(30){rand(256).chr}.join].pack("m").chomp)[0..39])
        write_attribute('token_expiry', (hours || Authentication::Configuration[:security_token_life]).hours.from_now)
        update_without_callbacks
        return self.security_token
      end
    end # module
  end # module
end # module