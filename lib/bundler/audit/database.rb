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

require 'bundler/audit/advisory'

require 'time'
require 'yaml'

module Bundler
  module Audit
    #
    # Represents the directory of advisories, grouped by gem name
    # and CVE number.
    #
    class Database

      class DownloadFailed < RuntimeError
      end

      class UpdateFailed < RuntimeError
      end

      #
      # Raised when the database itself violates the ingestion boundary,
      # e.g. a path escapes the database root or two advisories declare
      # conflicting aliases.
      #
      class InvalidDatabaseError < StandardError
      end

      # Raised when an advisory file cannot be ingested.
      class InvalidAdvisoryError < StandardError
      end

      # Git URL of the ruby-advisory-db.
      URL = 'https://github.com/rubysec/ruby-advisory-db.git'

      # Maximum allowed size of a single advisory YAML file (1 MiB).
      MAX_ADVISORY_SIZE = 1024 * 1024

      # Path to the user's copy of the ruby-advisory-db.
      USER_PATH = File.expand_path(File.join(Gem.user_home,'.local','share','ruby-advisory-db'))

      # Default path to the ruby-advisory-db.
      #
      # @since 0.8.0
      DEFAULT_PATH = ENV.fetch('BUNDLER_AUDIT_DB',USER_PATH)

      # The path to the advisory database.
      #
      # @return [String]
      attr_reader :path

      #
      # Initializes the Advisory Database.
      #
      # @param [String] path
      #   The path to the advisory database.
      #
      # @raise [ArgumentError]
      #   The path was not a directory.
      #
      def initialize(path=self.class.path)
        unless File.directory?(path)
          raise(ArgumentError,"#{path.dump} is not a directory")
        end

        @path = File.realpath(path)
      end

      #
      # The default path for the database.
      #
      # @return [String]
      #   The path to the database directory.
      #
      def self.path
        DEFAULT_PATH
      end

      #
      # Tests whether the database exists.
      #
      # @param [String] path
      #   The given path of the database to check.
      #
      # @return [Boolean]
      #
      # @since 0.8.0
      #
      def self.exists?(path=DEFAULT_PATH)
        File.directory?(path) && !(Dir.entries(path) - %w[. ..]).empty?
      end

      #
      # Downloads the ruby-advisory-db.
      #
      # @param [Hash] options
      #   Additional options.
      #
      # @option options [String] :path (DEFAULT_PATH)
      #   The destination path for the new ruby-advisory-db.
      #
      # @option options [Boolean] :quiet
      #   Specify whether `git` should be `--quiet`.
      #
      # @return [Database]
      #   The newly downloaded database.
      #
      # @raise [DownloadFailed]
      #   Indicates that the download failed.
      #
      # @note
      #   Requires network access.
      #
      # @since 0.8.0
      #
      def self.download(options={})
        unless (options.keys - [:path, :quiet]).empty?
          raise(ArgumentError,"Invalid option(s)")
        end

        path = options.fetch(:path,DEFAULT_PATH)

        command = %w[git clone]
        command << '--quiet' if options[:quiet]
        command << URL << path

        unless system(*command)
          raise(DownloadFailed,"failed to download #{URL} to #{path.inspect}")
        end

        return new(path)
      end

      #
      # Updates the ruby-advisory-db.
      #
      # @param [Hash] options
      #   Additional options.
      #
      # @option options [Boolean] :quiet
      #   Specify whether `git` should be `--quiet`.
      #
      # @return [Boolean]
      #   Specifies whether the update was successful.
      #
      # @raise [ArgumentError]
      #   Invalid options were given.
      #
      # @note
      #   Requires network access.
      #
      # @since 0.3.0
      #
      # @deprecated Use {#update!} instead.
      #
      def self.update!(options={})
        raise "Invalid option(s)" unless (options.keys - [:quiet]).empty?

        if File.directory?(DEFAULT_PATH)
          begin
            new(DEFAULT_PATH).update!(options)
          rescue UpdateFailed then false
          end
        else
          begin
            download(options.merge(path: DEFAULT_PATH))
          rescue DownloadFailed then false
          end
        end
      end

      #
      # Determines if the database is a git repository.
      #
      # @return [Boolean]
      #
      # @since 0.8.0
      #
      def git?
        File.directory?(File.join(@path,'.git'))
      end

      #
      # Updates the ruby-advisory-db.
      #
      # @param [Hash] options
      #   Additional options.
      #
      # @option options [Boolean] :quiet
      #   Specify whether `git` should be `--quiet`.
      #
      # @return [true, nil]
      #   * `true` - the ruby-advisory-db git repository was successfully
      #     updated.
      #   * `nil` - the ruby-advisory-db is not a git repository or the `git`
      #     command is not installed.
      #
      # @raise [UpdateFailed]
      #   Could not update the ruby-advisory-db git repository.
      #
      # @since 0.8.0
      #
      def update!(options={})
        if git?
          Dir.chdir(@path) do
            command = %w[git pull]
            command << '--quiet' if options[:quiet]
            command << 'origin' << 'master'

            unless system(*command)
              raise(UpdateFailed,"failed to update #{@path.inspect}")
            end

            return true
          end
        end
      end

      #
      # The last commit ID of the repository.
      #
      # @return [String, nil]
      #   The commit hash or `nil` if the database is not a git repository.
      #
      # @since 0.9.0
      #
      def commit_id
        if git?
          Dir.chdir(@path) do
            `git rev-parse HEAD`.chomp
          end
        end
      end

      #
      # Determines the time when the database was last updated.
      #
      # @return [Time]
      #
      # @since 0.8.0
      #
      def last_updated_at
        if git?
          Dir.chdir(@path) do
            Time.parse(`git log --date=iso8601 --pretty="%cd" -1`)
          end
        else
          File.mtime(@path)
        end
      end

      #
      # Enumerates over every advisory in the database.
      #
      # @yield [advisory]
      #   If a block is given, it will be passed each advisory.
      #
      # @yieldparam [Advisory] advisory
      #   An advisory from the database.
      #
      # @return [Enumerator]
      #   If no block is given, an Enumerator will be returned.
      #
      def advisories(&block)
        return enum_for(__method__) unless block_given?

        each_advisory do |advisory|
          yield advisory
        end
      end

      #
      # Enumerates over advisories for the given gem.
      #
      # @param [String] name
      #   The gem name to lookup.
      #
      # @yield [advisory]
      #   If a block is given, each advisory for the given gem will be yielded.
      #
      # @yieldparam [Advisory] advisory
      #   An advisory for the given gem.
      #
      # @return [Enumerator]
      #   If no block is given, an Enumerator will be returned.
      #
      def advisories_for(name)
        return enum_for(__method__,name) unless block_given?

        each_advisory_for(name) do |advisory|
          yield advisory
        end
      end

      #
      # Verifies whether the gem is effected by any advisories.
      #
      # @param [Gem::Specification] gem
      #   The gem to verify.
      #
      # @yield [advisory]
      #   If a block is given, it will be passed advisories that effect
      #   the gem.
      #
      # @yieldparam [Advisory] advisory
      #   An advisory that effects the specific version of the gem.
      #
      # @return [Enumerator]
      #   If no block is given, an Enumerator will be returned.
      #
      def check_gem(gem)
        return enum_for(__method__,gem) unless block_given?

        advisories_for(gem.name) do |advisory|
          if advisory.vulnerable?(gem.version)
            yield advisory
          end
        end
      end

      #
      # The number of advisories within the database.
      #
      # @return [Integer]
      #   The number of advisories.
      #
      def size
        each_advisory_path.count
      end

      #
      # Converts the database to a String.
      #
      # @return [String]
      #   The path to the database.
      #
      def to_s
        @path
      end

      #
      # Inspects the database.
      #
      # @return [String]
      #   The inspected database.
      #
      def inspect
        "#<#{self.class}:#{self}>"
      end

      protected

      #
      # Enumerates over every valid advisory in the database, rejecting
      # conflicting aliases.
      #
      # @yield [advisory]
      #   The given block will be passed each advisory.
      #
      # @yieldparam [Advisory] advisory
      #   An advisory from the database.
      #
      # @raise [InvalidDatabaseError]
      #   Two advisories for the same gem declare the same identifier but
      #   disagree about the affected versions.
      #
      def each_advisory(&block)
        return enum_for(__method__) unless block_given?

        each_advisory_path do |path|
          yield load_advisory(path)
        end
      end

      #
      # Enumerates over every valid advisory for the given gem.
      #
      # @param [String] name
      #   The gem name to lookup.
      #
      # @yield [advisory]
      #   The given block will be passed each advisory for the gem.
      #
      # @yieldparam [Advisory] advisory
      #   An advisory for the given gem.
      #
      def each_advisory_for(name,&block)
        return enum_for(__method__,name) unless block_given?

        registered_aliases = {}

        each_advisory_path_for(name) do |path|
          advisory = load_advisory(path)

          advisory.qualified_identifiers.each do |identifier|
            existing = registered_aliases[identifier]

            # A shared alias is only a conflict when one of the records
            # claims the identifier as its own primary ID (its file name)
            # but disagrees with the other record about the version ranges.
            if existing &&
               (existing.id == identifier || advisory.id == identifier) &&
               conflicting_aliases?(existing,advisory)
              raise(InvalidDatabaseError,
                    "conflicting advisories share identifier #{identifier.inspect}: " \
                    "#{existing.path.dump} and #{advisory.path.dump}")
            end

            registered_aliases[identifier] ||= advisory
          end

          yield advisory
        end
      end

      #
      # Enumerates over every advisory path in the database.
      #
      # @yield [path]
      #   The given block will be passed each advisory path.
      #
      # @yieldparam [String] path
      #   A path to an advisory `.yml` file.
      #
      # @raise [InvalidDatabaseError]
      #   A path is a symlink, is not a regular file, exceeds
      #   {MAX_ADVISORY_SIZE}, or escapes the database root directory.
      #
      def each_advisory_path(&block)
        return enum_for(__method__) unless block_given?

        each_gem_directory do |gem_directory|
          Dir.children(gem_directory).sort.each do |entry|
            next unless entry.end_with?('.yml')

            yield safe_advisory_path(File.join(gem_directory,entry))
          end
        end
      end

      #
      # Enumerates over the advisories for the given gem.
      #
      # @param [String] name
      #   The gem of the gem.
      #
      # @yield [path]
      #   The given block will be passed each advisory path.
      #
      # @yieldparam [String] path
      #   A path to an advisory `.yml` file.
      #
      # @raise [InvalidDatabaseError]
      #   The gem name is unsafe, a path is a symlink or non-regular file,
      #   exceeds {MAX_ADVISORY_SIZE}, or escapes the database root.
      #
      def each_advisory_path_for(name,&block)
        return enum_for(__method__,name) unless block_given?

        # A database does not have to contain advisories for every gem.
        return unless name.is_a?(String)
        return if name.empty? || name =~ /\A\.\.?\z/ || name !~ /\A[A-Za-z0-9._-]+\z/

        gem_directory = File.join(@path,'gems',name)

        return unless File.directory?(gem_directory) && !File.symlink?(gem_directory)

        ensure_within_root!(gem_directory)

        Dir.children(gem_directory).sort.each do |entry|
          next unless entry.end_with?('.yml')

          yield safe_advisory_path(File.join(gem_directory,entry))
        end
      end

      #
      # Enumerates over the gem directories within the database.
      #
      def each_gem_directory
        gems_root = File.join(@path,'gems')

        return unless File.directory?(gems_root)

        Dir.children(gems_root).sort.each do |entry|
          path = File.join(gems_root,entry)

          unless File.lstat(path).directory? && !File.symlink?(path)
            raise(InvalidDatabaseError,
                  "non-directory or symlink gem entry found in database: #{path.dump}")
          end

          ensure_within_root!(path)

          yield path
        end
      end

      #
      # Validates that an advisory path refers to a regular, non-symlink
      # file inside the database root and that it does not exceed
      # {MAX_ADVISORY_SIZE}.
      #
      def safe_advisory_path(path)
        stat = begin
                 File.lstat(path)
               rescue Errno::ENOENT
                 raise(InvalidDatabaseError,
                       "advisory path disappeared while reading the database: #{path.dump}")
               end

        if stat.symlink?
          raise(InvalidDatabaseError,
                "symlinked advisory files are not allowed: #{path.dump}")
        end

        unless stat.file?
          raise(InvalidDatabaseError,
                "only regular advisory files are allowed: #{path.dump}")
        end

        if stat.size > MAX_ADVISORY_SIZE
          raise(InvalidDatabaseError,
                "advisory file #{path.dump} is #{stat.size} bytes, " \
                "which exceeds the limit of #{MAX_ADVISORY_SIZE} bytes")
        end

        ensure_within_root!(path)

        return path
      end

      #
      # Ensures the real path of an entry stays inside the database root,
      # blocking hard links or bind-mount style escapes that `lstat` alone
      # cannot detect.
      #
      def ensure_within_root!(path)
        real_path = File.realpath(path)

        unless real_path == @path ||
               real_path.start_with?(@path + File::SEPARATOR)
          raise(InvalidDatabaseError,
                "database entry escapes the database root: #{path.dump}")
        end
      rescue Errno::ENOENT
        raise(InvalidDatabaseError,
              "database entry does not exist: #{path.dump}")
      end

      #
      # Loads an advisory file, converting schema errors into the
      # database-level exception so ingest failures never silently become
      # clean scans.
      #
      def load_advisory(path)
        Advisory.load(path)
      rescue Advisory::InvalidAdvisoryError => error
        raise(InvalidAdvisoryError,error.message)
      end

      #
      # Determines whether two advisories sharing an identifier make
      # incompatible claims about the affected versions.
      #
      def conflicting_aliases?(first,second)
        first.patched_versions.map(&:to_s) != second.patched_versions.map(&:to_s) ||
          first.unaffected_versions.map(&:to_s) != second.unaffected_versions.map(&:to_s)
      end

    end
  end
end
