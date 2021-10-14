# frozen_string_literal: true

require "webauthn/ios_attestation_response"
require "webauthn/public_key_credential/creation_options"
require "webauthn/public_key_credential/request_options"
require "webauthn/public_key_credential_with_assertion"
require "webauthn/public_key_credential_with_attestation"

module WebAuthn
  module Credential
    def self.options_for_create(**keyword_arguments)
      WebAuthn::PublicKeyCredential::CreationOptions.new(**keyword_arguments)
    end

    def self.options_for_get(**keyword_arguments)
      WebAuthn::PublicKeyCredential::RequestOptions.new(**keyword_arguments)
    end

    def self.from_create(credential, response_class_override = nil)
      WebAuthn::PublicKeyCredentialWithAttestation.from_client(credential, response_class_override)
    end

    def self.from_get(credential)
      WebAuthn::PublicKeyCredentialWithAssertion.from_client(credential)
    end

    def self.from_ios_attest(attestation_string:, key_id:, app_id:, challenge:)
      data = {
        type: WebAuthn::TYPE_PUBLIC_KEY,
        id: key_id,
        rawId: key_id,
        response: {
          attestationObject: attestation_string,
          appId: app_id,
          keyId: key_id,
          challenge: challenge
        }
      }.with_indifferent_access
      WebAuthn::PublicKeyCredentialWithAttestation.from_client(data, WebAuthn::IOSAttestationResponse)
    end
  end
end
