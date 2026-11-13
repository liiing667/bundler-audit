#
# Copyright (c) 2013-2026 Hal Brodigan (postmodern.mod3 at gmail.com)
#
# bundler-audit is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# bundler-audit is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with bundler-audit.  If not, see <https://www.gnu.org/licenses/>.
#

require 'date'
require 'yaml'

module Bundler
  module Audit
    #
    # Represents an advisory loaded from the {Database}.
    #
    class Advisory < Struct.new(:path,
                                :id,
                                :url,
                                :title,
                                :date,
                                :description,
                                :cvss_v2,
                                :cvss_v3,
                                :cvss_v4,
                                :cve,
                                :osvdb,
                                :ghsa,
                                :unaffected_versions,
                                :patched_versions)

      #
      # Raised when an advisory YAML file is malformed or violates the
      # advisory schema.
      #
      class InvalidAdvisoryError < StandardError
      end

      # Top-level keys allowed within an advisory YAML document.
      VALID_KEYS = %w[
        gem
        cve
        osvdb
        ghsa
        url
        title
        date
        description
        cvss_v2
        cvss_v3
        cvss_v4
        framework
        library
        platform
        related
        vendor_patch
        unaffected_versions
        patched_versions
      ].freeze

      # Keys which must contain a String when present.
      STRING_KEYS = %w[
        gem
        cve
        ghsa
        url
        title
        description
        framework
        library
        platform
      ].freeze

      # Keys which must contain an Array of Strings when present.
      VERSION_KEYS = %w[unaffected_versions patched_versions].freeze

      # Keys which must contain a Numeric CVSS score within `0.0..10.0`.
      CVSS_KEYS = %w[cvss_v2 cvss_v3 cvss_v4].freeze

      # @see https://cve.mitre.org/cve/identifiers/tech-guidance.html
      CVE_REGEXP  = /\A\d{4}-\d{4,7}\z/.freeze

      # @see https://github.com/github/advisory-database
      GHSA_REGEXP = /\A[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}\z/.freeze

      OSVDB_REGEXP = /\A\d+\z/.freeze

      #
      # Loads the advisory from a YAML file.
      #
      # @param [String] path
      #   The path to the advisory YAML file.
      #
      # @return [Advisory]
      #
      # @raise [InvalidAdvisoryError]
      #   The advisory YAML was malformed, contained an unsupported key,
      #   violated the schema, or contained an invalid/empty version range.
      #
      # @api semipublic
      #
      def self.load(path)
        id   = File.basename(path).chomp('.yml')
        data = load_yaml(path)

        validate_schema!(data,path)

        validate_identifiers!(data,path)

        unaffected_versions = parse_versions(data['unaffected_versions'],path)
        patched_versions    = parse_versions(data['patched_versions'],path)

        return new(
          path,
          id,
          data['url'],
          data['title'],
          data['date'],
          data['description'],
          data['cvss_v2'],
          data['cvss_v3'],
          data['cvss_v4'],
          data['cve'],
          data['osvdb'],
          data['ghsa'],
          unaffected_versions,
          patched_versions
        )
      end

      #
      # Safely parses the YAML document, only allowing plain data and
      # {Date} values. YAML aliases, custom tags or arbitrary objects are
      # rejected.
      #
      def self.load_yaml(path)
        File.open(path) do |yaml|
          if Psych::VERSION >= '3.1.0'
            YAML.safe_load(yaml, permitted_classes: [Date])
          else
            # XXX: psych < 3.1.0 YAML.safe_load calling convention
            YAML.safe_load(yaml, [Date])
          end
        end
      rescue Psych::Exception => error
        raise(InvalidAdvisoryError,"invalid YAML in advisory #{path.dump}: #{error.message}")
      end
      private_class_method :load_yaml

      #
      # Validates the structure and value types of the advisory Hash.
      #
      def self.validate_schema!(data,path)
        unless data.kind_of?(Hash)
          raise(InvalidAdvisoryError,"advisory data in #{path.dump} was not a Hash")
        end

        unknown_keys = data.keys - VALID_KEYS
        unless unknown_keys.empty?
          raise(InvalidAdvisoryError,
                "advisory #{path.dump} contains unsupported key(s): #{unknown_keys.map(&:inspect).join(', ')}")
        end

        unless data['gem'].is_a?(String) && !data['gem'].empty?
          raise(InvalidAdvisoryError,
                "advisory #{path.dump} is missing a non-empty String 'gem' value")
        end

        STRING_KEYS.each do |key|
          value = data[key]

          if !value.nil? && !value.is_a?(String)
            raise(InvalidAdvisoryError,
                  "advisory #{path.dump} key #{key.inspect} must be a String")
          end
        end

        if data.key?('osvdb') && !(data['osvdb'].is_a?(Integer) ||
                                   (data['osvdb'].is_a?(String) && data['osvdb'] =~ OSVDB_REGEXP))
          raise(InvalidAdvisoryError,
                "advisory #{path.dump} key 'osvdb' must be an Integer or a numeric String")
        end

        if data.key?('date') && !data['date'].nil? && !data['date'].is_a?(Date)
          raise(InvalidAdvisoryError,
                "advisory #{path.dump} key 'date' must be a Date")
        end

        CVSS_KEYS.each do |key|
          value = data[key]

          if !value.nil? && (!value.is_a?(Numeric) || !(0.0..10.0).include?(value.to_f))
            raise(InvalidAdvisoryError,
                  "advisory #{path.dump} key #{key.inspect} must be a Numeric score between 0.0 and 10.0")
          end
        end

        VERSION_KEYS.each do |key|
          value = data[key]

          if !value.nil? &&
             (!value.is_a?(Array) || value.any? { |entry| !entry.is_a?(String) || entry.strip.empty? })
            raise(InvalidAdvisoryError,
                  "advisory #{path.dump} key #{key.inspect} must be an Array of non-empty Strings")
          end
        end

        if data.key?('related')
          validate_related!(data['related'],path)
        end

        if data.key?('vendor_patch') &&
           (!data['vendor_patch'].is_a?(Array) ||
            data['vendor_patch'].any? { |entry| !entry.is_a?(String) })
          raise(InvalidAdvisoryError,
                "advisory #{path.dump} key 'vendor_patch' must be an Array of Strings")
        end
      end
      private_class_method :validate_schema!

      #
      # Validates the structure of the optional `related` mapping.
      #
      def self.validate_related!(related,path)
        unless related.is_a?(Hash)
          raise(InvalidAdvisoryError,
                "advisory #{path.dump} key 'related' must be a Hash")
        end

        related.each do |key,value|
          unless key.is_a?(String) && value.is_a?(Array) &&
                 value.all? { |entry| entry.is_a?(String) || entry.is_a?(Integer) }
            raise(InvalidAdvisoryError,
                  "advisory #{path.dump} key 'related' must map String keys to Arrays of Strings or Integers")
          end
        end
      end
      private_class_method :validate_related!

      #
      # Validates the formats of the optional identifiers.
      #
      def self.validate_identifiers!(data,path)
        if data['cve'] && data['cve'] !~ CVE_REGEXP
          raise(InvalidAdvisoryError,
                "advisory #{path.dump} has an invalid 'cve' identifier: #{data['cve'].inspect}")
        end

        if data['ghsa'] && data['ghsa'] !~ GHSA_REGEXP
          raise(InvalidAdvisoryError,
                "advisory #{path.dump} has an invalid 'ghsa' identifier: #{data['ghsa'].inspect}")
        end

        if data['osvdb'] && data['osvdb'].to_s !~ OSVDB_REGEXP
          raise(InvalidAdvisoryError,
                "advisory #{path.dump} has an invalid 'osvdb' identifier: #{data['osvdb'].inspect}")
        end
      end
      private_class_method :validate_identifiers!

      #
      # Parses a list of version requirement strings into
      # {Gem::Requirement} objects, rejecting malformed requirements and
      # requirements that no version could ever satisfy (empty intervals).
      #
      def self.parse_versions(versions,path)
        Array(versions).map do |version|
          requirement = begin
                          Gem::Requirement.new(*version.split(', '))
                        rescue Gem::Requirement::BadRequirementError => error
                          raise(InvalidAdvisoryError,
                                "advisory #{path.dump} contains an invalid version requirement #{version.inspect}: #{error.message}")
                        end

          if empty_requirement?(requirement)
            raise(InvalidAdvisoryError,
                  "advisory #{path.dump} contains an empty version interval: #{version.inspect}")
          end

          requirement
        end
      end
      private_class_method :parse_versions

      #
      # Determines whether a {Gem::Requirement} can never be satisfied.
      #
      def self.empty_requirement?(requirement)
        exact_versions = requirement.requirements.select { |op,_| op == '=' }.map(&:last)

        return true if exact_versions.uniq.size > 1

        excluded_versions = requirement.requirements.select { |op,_| op == '!=' }.map(&:last)

        return true if exact_versions.any? { |version| excluded_versions.include?(version) }

        lower_bounds = requirement.requirements.select { |op,_|
          ['>=', '>', '~>'].include?(op)
        }
        upper_bounds = requirement.requirements.select { |op,_|
          ['<=', '<'].include?(op)
        }

        lower_bounds.any? do |lower_op,lower_version|
          upper_bounds.any? do |upper_op,upper_version|
            comparison = lower_version <=> upper_version

            comparison > 0 ||
              (comparison == 0 && (lower_op == '>' || upper_op == '<'))
          end
        end
      end
      private_class_method :empty_requirement?

      #
      # The fully-qualified identifiers of the advisory.
      #
      # @return [Array<String>]
      #
      def qualified_identifiers
        [id, *identifiers]
      end

      #
      # The CVE identifier.
      #
      # @return [String, nil]
      #
      def cve_id
        "CVE-#{cve}" if cve
      end

      #
      # The OSVDB identifier.
      #
      # @return [String, nil]
      #
      def osvdb_id
        "OSVDB-#{osvdb}" if osvdb
      end

      #
      # The GHSA (GitHub Security Advisory) identifier
      #
      # @return [String, nil]
      #
      # @since 0.7.0
      #
      def ghsa_id
        "GHSA-#{ghsa}" if ghsa
      end

      #
      # Return a compacted list of all ids
      #
      # @return [Array<String>]
      #
      # @since 0.7.0
      #
      def identifiers
        [
          cve_id,
          osvdb_id,
          ghsa_id
        ].compact
      end

      #
      # Determines how critical the vulnerability is.
      #
      # @return [:none, :low, :medium, :high, :critical, nil]
      #   The criticality of the vulnerability based on the CVSS score.
      #
      def criticality
        if cvss_v4 || cvss_v3
          case cvss_v4 || cvss_v3
          when 0.0       then :none
          when 0.1..3.9  then :low
          when 4.0..6.9  then :medium
          when 7.0..8.9  then :high
          when 9.0..10.0 then :critical
          end
        elsif cvss_v2
          case cvss_v2
          when 0.0..3.9  then :low
          when 4.0..6.9  then :medium
          when 7.0..10.0 then :high
          end
        end
      end

      #
      # Checks whether the version is not affected by the advisory.
      #
      # @param [Gem::Version] version
      #   The version to compare against {#unaffected_versions}.
      #
      # @return [Boolean]
      #   Specifies whether the version is not affected by the advisory.
      #
      # @since 0.2.0
      #
      def unaffected?(version)
        unaffected_versions.any? do |unaffected_version|
          unaffected_version === version
        end
      end

      #
      # Checks whether the version is patched against the advisory.
      #
      # @param [Gem::Version] version
      #   The version to compare against {#patched_versions}.
      #
      # @return [Boolean]
      #   Specifies whether the version is patched against the advisory.
      #
      # @since 0.2.0
      #
      def patched?(version)
        patched_versions.any? do |patched_version|
          patched_version === version
        end
      end

      #
      # Checks whether the version is vulnerable to the advisory.
      #
      # @param [Gem::Version] version
      #   The version to compare against {#patched_versions}.
      #
      # @return [Boolean]
      #   Specifies whether the version is vulnerable to the advisory or not.
      #
      def vulnerable?(version)
        !patched?(version) && !unaffected?(version)
      end

      #
      # Compares two advisories.
      #
      # @param [Advisory] other
      #
      # @return [Boolean]
      #
      def ==(other)
        id == other.id
      end

      #
      # Converts the advisory to a Hash.
      #
      # @return [Hash{Symbol => Object}]
      #
      def to_h
        super.merge({
          criticality: criticality
        })
      end

      alias to_s id

    end
  end
end
