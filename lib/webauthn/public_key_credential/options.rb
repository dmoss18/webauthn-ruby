# frozen_string_literal: true

require 'awrence'
require 'securerandom'

module WebAuthn
  class PublicKeyCredential
    class Options
      attr_reader :timeout, :extensions

      def initialize(timeout: default_timeout, extensions: nil)
        @timeout = timeout
        @extensions = extensions
      end

      def challenge
        encoder.encode(raw_challenge)
      end

      # Argument wildcard for Ruby on Rails controller automatic object JSON serialization
      def as_json(*)
        to_hash.to_camelback_keys
      end

      private

      def to_hash
        hash = {}

        attributes.each do |attribute_name|
          value = send(attribute_name)

          value = value.as_json if value.respond_to?(:as_json)

          hash[attribute_name] = value if value
        end

        hash
      end

      def attributes
        [:challenge, :timeout, :extensions]
      end

      def encoder
        WebAuthn.configuration.encoder
      end

      def raw_challenge
        @raw_challenge ||= SecureRandom.random_bytes(WebAuthn::SecurityUtils::CHALLENGE_LENGTH)
      end

      def default_timeout
        configuration.credential_options_timeout
      end

      def configuration
        WebAuthn.configuration
      end

      def as_public_key_descriptors(ids)
        Array(ids).map { |id| { type: TYPE_PUBLIC_KEY, id: id } }
      end
    end
  end
end
