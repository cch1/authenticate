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
      def authenticate(login, password)
        u = self.find_by_login(login) rescue nil
        u && u.password?(password) ? u : nil
      end 

      def authenticate_by_token(id, token)
        u = self.find(id) rescue nil
        u && u.token?(token) ? u : nil
      end      
    end

    module InstanceMethods
      def initialize(*args)
        super
        @new_password = false
      end
  
      def password?(password)
        match = (AuthenticatedUser.encrypt(self.salt, password) == self.hashed_password)
        match && verified && !deleted
      end
      
      def token?(token)
        sleep(1)
        match = (token == security_token) 
        match && !self.token_expired? && self.update_expiry
      end
      
      def token_expired?
        raise Authenticate::InvalidTokenExpiry if self.security_token and !self.token_expiry
        self.security_token and (Time.now > self.token_expiry.to_time)
      end
  
      def update_expiry
        write_attribute('token_expiry', [self.token_expiry.to_time, Time.at(Time.now.to_i + 600 * 1000)].min)
        update_without_callbacks
      end
  
      def valid_password?
        hashed_password && !(hashed_password.length == 0)
      end
      
      def generate_security_token(hours = nil)
        if not hours.nil? or self.security_token.nil? or self.token_expiry.nil? or 
            (Time.now.to_i + token_lifetime / 2) >= self.token_expiry.to_i
          return new_security_token(hours)
        else
          return self.security_token
        end
      end
  
      def set_delete_after
        hours = Authentication::Configuration[:delete_delay] * 24
        write_attribute('deleted', true)
        write_attribute('delete_after', Time.at(Time.now.to_i + hours * 60 * 60))
  
        # Generate and return a token here, so that it expires at
        # the same time that the account deletion takes effect.
        return generate_security_token(hours)
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
        write_attribute('token_expiry', Time.at(Time.now.to_i + token_lifetime(hours)))
        update_without_callbacks
        return self.security_token
      end
  
      def token_lifetime(hours = nil)
        if hours.nil?
          # Get configured token life, or default (24)
          Authentication::Configuration[:security_token_life] * 60 * 60
        else
          hours * 60 * 60
        end
      end # method
    end # module
  end # module
end # module