module Authenticate
  module AuthenticatedUser
    module ClassMethods
      def authenticated
        require 'digest/sha2'

        attr_reader :_password

        validates_presence_of :login
        validates_uniqueness_of :login

        after_save :clear_password

        extend SingletonMethods
        include InstanceMethods
      end

      # This nasty macro creates accessors that can't be replaced by included modules, so we intercept it when
      # applied to the password attribute and replace with our own version.
      def validates_confirmation_of(*args)
        options = args.extract_options!.symbolize_keys
        safe_attrs = args.flatten.reject{|attr| :password == attr}
        super(*(safe_attrs << options), &block) if safe_attrs.any?
        if args.flatten.include?(:password)
          attr_reader :_password_confirmation
          config = {:on => :save}.merge(options)
          validates_each(:password, config) do |record, attr_name, value|
            unless record._password_confirmation.nil? or value == record._password_confirmation
              record.errors.add(attr_name, :confirmation, :default => config[:message])
            end
          end
        end
      end

      # This is a special case where presence is indirectly inferred and Rails does not use
      # #validates_each
      def validates_presence_of(*args, &block)
        options = args.extract_options!.symbolize_keys
        safe_attrs = args.flatten.reject{|attr| :password == attr}
        super(*(safe_attrs << options), &block) if safe_attrs.any?
        if args.flatten.include?(:password)
          config = {:on => :save}.merge(options)
          send(validation_method(config[:on]), config) do |record|
            invalid = [nil, fingerprint(record.salt, '')]
            record.errors.add(:password, :blank, :default => config[:message]) if invalid.include?(record.hashed_password)
          end
        end
      end

      # Use cleartext password values for "standard" validations (validates_X_of) and only apply
      # them when we have testable values.
      def validates_each(*args, &block)
        options = args.extract_options!.symbolize_keys
        safe_attrs = args.flatten.reject{|attr| :password == attr}
        super(*(safe_attrs << options), &block) if safe_attrs.any?
        if args.flatten.include?(:password)
          send(validation_method(options[:on] || :save), options) do |record|
            value = record._password # Get the cleartext version
            yield record, :password, value unless value.nil? || (value.blank? && options[:allow_blank])
          end
        end
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

      # Hash the password and salt iteratively to produce a digest.  Iteration has been questioned in the cryptographic
      # community (see reference one below), but assumed practical in the applied art of password management (as shown in
      # references two and three) in increasing the amount of time required to execute a dictionary attack.
      # http://www.linuxworld.com/cgi-bin/mailto/x_linux.cgi?pagetosend=/export/home/httpd/linuxworld/news/2007/111207-hash.html
      # http://macshadows.com/kb/index.php?title=Mac_OS_X_password_hashes
      # http://www.adamberent.com/documents/KeyIterations&CryptoSalts.pdf
      def fingerprint(salt, password)
        return password unless password && salt
        hash_length = self.columns_hash['hashed_password'].limit
        iterated_hash_length = Authenticate::Configuration[:compatibility_mode] ? hash_length : 0
        key = salt + password
        # Light up the CPU
        raise "Missing configuration value" unless (Authenticate::Configuration[:hash_iterations] && (Authenticate::Configuration[:hash_iterations] > 0))
        Authenticate::Configuration[:hash_iterations].times { key = Digest::SHA512.hexdigest(key)[0..iterated_hash_length - 1] }
        key[0, hash_length]
      end

      # Encrypt the password with reversible XOR maskion.
      def mask(cleartext)
        cleartext && '*' * cleartext.length
      end
    end

    module InstanceMethods
      def password?(password)
        self.class.fingerprint(self.salt, password) == self.hashed_password
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
          # This code smell reflects poor modelling: authentication is not identification, and auth tokens should not be
          # attributes of a User.  We use the class method so as to not fail due to unrelated validations (or accidentally
          # update the user with invalid attributes).
          self.class.update_all({:token_expiry => token_expiry}, {:id => self.id})
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

      # Change the user's password to the given password.  It is not possible to change an unknowable
      # password to nil with this setter -use #clear_password! instead.
      def password=(pw)
        return pw if pw == self.class.mask(@_password) # This is assumed to be a round-trip scenario.
        self.hashed_password = self.class.fingerprint(salt, pw)
        @_password = pw
      end

      # Return a masked version of the password.  Note that the masking preserves gross
      # characteristics for visual feedback only.
      def password
        self.class.mask(@_password)
      end

      # Because nil is a sentinel value (representing an unknownable password), an
      # out-of-band method must be used to clear a password (set it to nil).
      def clear_password!
        self.hashed_password = self.class.fingerprint(salt, nil)
        @_password = nil
      end

      def password_confirmation=(pwc)
        return pwc if pwc == self.class.mask(@_password_confirmation) # This is assumed to be a round-trip scenario.
        @_password_confirmation = pwc
      end

      def password_confirmation
        self.class.mask(@_password_confirmation)
      end

      # Normalize the OpenID identity URL on assignment
      def identity_url=(u)
        u = OpenID.normalize_url(u) if defined?(OpenID) rescue u # Not pretty, but OpenID raises too many exceptions.
        write_attribute(:identity_url, u)
      end

      protected
      def salt
        self[:salt] ||= self.class.salt
      end

      # Expunge cleartext password from memory
      def clear_password
        @_password = @_password_confirmation = nil
      end

      # Generate a new security token valid for hours hours.  The token is Base64 encoded and stripped of newlines for URL and DB safety.
      def new_security_token(hours)
        token_length = self.class.columns_hash["security_token"].limit
        returning Digest::SHA512.hexdigest([Array.new(0.75 * token_length){rand(256).chr}.join].pack("m").gsub(/\n/, ''))[0, token_length] do |token|
          self.security_token = token
          self.token_expiry = hours.hours.from_now
          self.class.update_all({:token_expiry => token_expiry, :security_token => security_token}, {:id => self.id})
        end
      end
    end # module
  end # module
end # module