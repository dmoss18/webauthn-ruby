# frozen_string_literal: true

require 'cbor'
require 'forwardable'
require 'uri'
require 'openssl'

require 'webauthn/attestation_object'
require 'webauthn/authenticator_attestation_response'
require 'webauthn/client_data'
require 'webauthn/encoder'

module WebAuthn
  class AppIdVerificationError < VerificationError; end

  class IOSAttestationResponse < AuthenticatorAttestationResponse
    def self.from_client(response)
      encoder = WebAuthn.configuration.encoder

      new(
        encoder.decode(response['attestationObject']),
        response['appId'],
        response['challenge'],
        response['keyId']
      )
    end

    attr_reader :app_id, :challenge, :key_id

    def initialize(attestation_object, app_id, challenge, key_id)
      @attestation_object_bytes = attestation_object
      @app_id = app_id
      @challenge = challenge
      @key_id = key_id
    end

    # rubocop:disable Lint/UnusedMethodArgument
    def verify(expected_challenge, _expected_origin = nil, user_verification: nil, rp_id: nil)
      verify_item(:challenge, expected_challenge)
      verify_item(:authenticator_data)
      verify_item(:attested_credential)
      verify_item(:attestation_statement)
      verify_item(:rp_id, app_id)
      verify_item(:app_id, app_id)

      true
    end
    # rubocop:enable Lint/UnusedMethodArgument

    def client_data_json
      @client_data_json ||= { challenge: challenge }.to_json
    end

    # List of app ids, if you have multiple apps
    def acceptable_app_ids
      @acceptable_app_ids ||= ENV.fetch('IOS_ATTESTATION_APP_IDS', '')&.split(',')
    end

    def valid_app_id?(app_id)
      acceptable_app_ids.include? app_id
    end

    def valid_attestation_statement?
      client_data_hash = Digest::SHA256.digest(challenge)
      @attestation_type, @attestation_trust_path = attestation_object.valid_attestation_statement?(
        client_data_hash,
        { app_id: app_id, key_id: key_id }
      )
    end
  end
end
