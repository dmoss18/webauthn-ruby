# frozen_string_literal: true

require 'openssl'
require 'webauthn/encoder'
require 'webauthn/error'

module WebAuthn
  def self.configuration
    @configuration ||= Configuration.new
  end

  def self.configure
    yield(configuration)
  end

  class RootCertificateFinderNotSupportedError < Error; end

  class Configuration
    DEFAULT_ALGORITHMS = %w[ES256 PS256 RS256].compact.freeze

    attr_accessor :algorithms
    attr_accessor :encoding
    attr_accessor :origin
    attr_accessor :rp_id
    attr_accessor :rp_name
    attr_accessor :verify_attestation_statement
    attr_accessor :credential_options_timeout
    attr_accessor :silent_authentication
    attr_accessor :acceptable_attestation_types
    attr_reader :attestation_root_certificates_finders

    def initialize
      @algorithms = DEFAULT_ALGORITHMS.dup
      @encoding = WebAuthn::Encoder::STANDARD_ENCODING
      @verify_attestation_statement = true
      @credential_options_timeout = 120_000
      @silent_authentication = false
      @acceptable_attestation_types = %w[None Self Basic AttCA Basic_or_AttCA AnonCA]
      @attestation_root_certificates_finders = []
    end

    # This is the user-data encoder.
    # Used to decode user input and to encode data provided to the user.
    def encoder
      @encoder ||= WebAuthn::Encoder.new(encoding)
    end

    def attestation_root_certificates_finders=(finders)
      finders = [finders] unless finders.respond_to?(:each)

      finders.each do |finder|
        raise RootCertificateFinderNotSupportedError, 'Finder must implement `find` method' unless finder.respond_to?(:find)
      end

      @attestation_root_certificates_finders = finders
    end
  end
end
