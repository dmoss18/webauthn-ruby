# frozen_string_literal: true

require "openssl"
require "webauthn/attestation_statement/base"
require_relative "./apple"

module WebAuthn
  module AttestationStatement
    class AppleAppAttest < Apple
      # Source: https://www.apple.com/certificateauthority/private/
      ROOT_CERTIFICATE =
        OpenSSL::X509::Certificate.new(<<~PEM)
          -----BEGIN CERTIFICATE-----
          MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
          JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
          QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
          Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
          biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
          bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
          NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
          Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
          MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
          CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
          53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
          oyFraWVIyd/dganmrduC1bmTBGwD
          -----END CERTIFICATE-----
        PEM
      VALID_AAGUIDS = [
        'appattestdevelop',
        'appattest' # Should be followed by 7 0x00 bytes
      ].freeze

      def valid?(authenticator_data, client_data_hash, options = {})
        key_id = options[:key_id]
        app_id = options[:app_id]

        trustworthy? &&
          valid_nonce?(authenticator_data, client_data_hash) &&
          valid_attestation_certificate?(key_id) &&
          valid_app_id?(authenticator_data, app_id) &&
          valid_aaguid?(authenticator_data) &&
          valid_key_id?(authenticator_data, key_id) &&
          matching_public_key?(authenticator_data) &&
          [attestation_type, attestation_trust_path]
      end

      def valid_certificate_chain?(aaguid: nil, attestation_certificate_key_id: nil)
        attestation_root_certificates_store(
          aaguid: aaguid,
          attestation_certificate_key_id: attestation_certificate_key_id
        ).verify(ROOT_CERTIFICATE, attestation_trust_path)
      end

      # Create the SHA256 hash of the public key in credCert, and verify that it matches the key identifier from your app.
      def valid_attestation_certificate?(key_id)
        cred_cert_octet = cred_cert.public_key.public_key.to_octet_string(:uncompressed)
        actual_key_id = Digest::SHA256.digest(cred_cert_octet)
        decoded_key_id = Base64.decode64(key_id)
        actual_key_id == decoded_key_id
      end

      # Compute the SHA256 hash of your app’s App ID, and verify that it’s the same as the authenticator data’s RP ID hash.
      def valid_app_id?(authenticator_data, app_id)
        app_id_hash = Digest::SHA256.digest(app_id)
        authenticator_data.rp_id_hash == app_id_hash
      end

      def sign_count
        authenticator_data.sign_count
      end

      # Verify that the authenticator data’s aaguid field is either appattestdevelop if operating in the development environment,
      # or appattest followed by seven 0x00 bytes if operating in the production environment.
      def valid_aaguid?(authenticator_data)
        VALID_AAGUIDS.include? \
          authenticator_data.attested_credential_data.raw_aaguid
      end

      # Verify that the authenticator data’s credentialId field is the same as the key identifier.
      def valid_key_id?(authenticator_data, key_id)
        authenticator_data.credential.id == Base64.decode64(key_id)
      end

      def default_root_certificates
        [ROOT_CERTIFICATE]
      end

      def receipt
        statement['receipt']
      end
    end
  end
end
