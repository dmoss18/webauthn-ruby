# frozen_string_literal: true

require 'awrence'

module WebAuthn
  class PublicKeyCredential
    class Entity
      attr_reader :name

      def initialize(name:)
        @name = name
      end

      def as_json
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
        [:name]
      end
    end
  end
end
