require 'spec_helper'
require 'bundler/audit/database'
require 'tmpdir'

describe Bundler::Audit::Database do
  let(:vendored_advisories) do
    Dir[File.join(Fixtures::Database::PATH, 'gems/*/*.yml')].sort
  end

  describe ".path" do
    subject { described_class.path }

    it "it should be a directory" do
      expect(described_class.path).to be_truthy
    end
  end

  describe ".exists?" do
    subject { described_class }

    context "when the directory does not exist" do
      let(:path) { '/does/not/exist' }

      it { expect(subject.exists?(path)).to be(false) }
    end

    context "when the directory does exist" do
      context "but is empty" do
        let(:path) { Fixtures.join('empty_dir') }

        before { FileUtils.mkdir(path) }

        it { expect(subject.exists?(path)).to be(false) }

        after { FileUtils.rmdir(path) }
      end

      context "and there are files within the directory" do
        let(:path) { Fixtures.join('not_empty_dir') }

        before do
          FileUtils.mkdir(path)
          FileUtils.touch(File.join(path,'file.txt'))
        end

        it { expect(subject.exists?(path)).to be(true) }

        after { FileUtils.rm_r(path) }
      end
    end
  end

  describe ".download" do
    subject { described_class }

    let(:url)  { described_class::URL          }
    let(:path) { described_class::DEFAULT_PATH }

    it "should execute `git clone` with URL and DEFAULT_PATH" do
      expect(subject).to receive(:system).with('git', 'clone', url, path).and_return(true)
      expect(subject).to receive(:new)

      subject.download
    end

    context "with :path" do
      let(:url)  { described_class::URL          }
      let(:path) { Fixtures.join('new-database') }

      it "should execute `git clone` with the given output path" do
        expect(subject).to receive(:system).with('git', 'clone', url, path).and_return(true)
        expect(subject).to receive(:new)

        subject.download(path: path)
      end
    end

    context "with :quiet" do
      it "should execute `git clone` with the `--quiet` option" do
        expect(subject).to receive(:system).with('git', 'clone', '--quiet', url, path).and_return(true)
        expect(subject).to receive(:new)

        subject.download(quiet: true)
      end
    end

    context "when the command fails" do
      it do
        expect(subject).to receive(:system).with('git', 'clone', url, path).and_return(false)

        expect {
          subject.download
        }.to raise_error(described_class::DownloadFailed)
      end
    end

    context "with an unknown option" do
      it do
        expect {
          subject.download(foo: true)
        }.to raise_error(ArgumentError)
      end
    end
  end

  describe ".update!" do
    subject { described_class }

    context "when :path does not yet exist" do
      let(:dest_dir) { Fixtures.join('new-ruby-advisory-db') }

      before { stub_const("#{described_class}::DEFAULT_PATH",dest_dir) }

      let(:url)  { described_class::URL          }
      let(:path) { described_class::DEFAULT_PATH }

      it "should execute `git clone` and call .new" do
        expect(subject).to receive(:system).with('git', 'clone', url, path).and_return(true)
        expect(subject).to receive(:new)

        subject.update!(quiet: false)
      end

      context "when the `git clone` fails" do
        before { stub_const("#{described_class}::URL",'https://example.com/') }

        it do
          expect(subject).to receive(:system).with('git', 'clone', url, path).and_return(false)

          expect(subject.update!(quiet: false)).to eq(false)
        end
      end

      after { FileUtils.rm_rf(dest_dir) }
    end

    context "when :path already exists" do
      let(:dest_dir) { Fixtures.join('existing-ruby-advisory-db') }

      before { FileUtils.cp_r(Fixtures::Database::PATH,dest_dir) }
      before { stub_const("#{described_class}::DEFAULT_PATH",dest_dir) }

      it "should execute `git pull`" do
        expect_any_instance_of(subject).to receive(:system).with('git', 'pull', 'origin', 'master').and_return(true)

        subject.update!(quiet: false)
      end

      after { FileUtils.rm_rf(dest_dir) }

      context "when the `git pull` fails" do
        it do
          expect_any_instance_of(subject).to receive(:system).with('git', 'pull', 'origin', 'master').and_return(false)

          expect(subject.update!(quiet: false)).to eq(false)
        end
      end
    end

    context "when given an invalid option" do
      it do
        expect { subject.update!(foo: 1) }.to raise_error(RuntimeError)
      end
    end
  end

  describe "#initialize" do
    context "when given no arguments" do
      subject { described_class.new }

      it "should default path to path" do
        expect(subject.path).to eq(described_class.path)
      end
    end

    context "when given a directory" do
      let(:path) { Dir.tmpdir }

      subject { described_class.new(path) }

      it "should set #path" do
        expect(subject.path).to eq(path)
      end
    end

    context "when given an invalid directory" do
      it "should raise an ArgumentError" do
        expect {
          described_class.new('/foo/bar/baz')
        }.to raise_error(ArgumentError)
      end
    end
  end

  describe "#git?" do
    subject { described_class.new(path) }

    context "when a '.git' directory exists within the database" do
      let(:path) { Fixtures.join('mock-git-database') }

      before do
        FileUtils.mkdir(path)
        FileUtils.mkdir(File.join(path,'.git'))
      end

      it { expect(subject.git?).to be(true) }

      after { FileUtils.rm_rf(path) }
    end

    context "when no '.git' directory exists within the database" do
      let(:path) { Fixtures.join('mock-bare-database') }

      before do
        FileUtils.mkdir(path)
      end

      it { expect(subject.git?).to be(false) }

      after { FileUtils.rm_rf(path) }
    end
  end

  describe "#update!" do
    context "when the database is a git repository" do
      it do
        expect(subject).to receive(:system).with('git', 'pull', 'origin', 'master').and_return(true)

        subject.update!
      end

      context "when the :quiet option is given" do
        it do
          expect(subject).to receive(:system).with('git', 'pull', '--quiet', 'origin', 'master').and_return(true)

          subject.update!(quiet: true)
        end
      end

      context "when the `git pull` command fails" do
        it do
          expect(subject).to receive(:system).with('git', 'pull', 'origin', 'master').and_return(false)

          expect {
            subject.update!
          }.to raise_error(described_class::UpdateFailed)
        end
      end
    end

    context "when the database is a bare directory" do
      let(:path) { Fixtures.join('mock-bare-database') }

      before { FileUtils.mkdir(path) }

      subject { described_class.new(path) }

      it do
        expect(subject.update!).to be(nil)
      end

      after { FileUtils.rmdir(path) }
    end
  end

  describe "#commit_id" do
    context "when the database is a git repository" do
      let(:last_commit) { Fixtures::Database::COMMIT }

      it "should return the last commit ID" do
        expect(subject.commit_id).to be == last_commit
      end
    end

    context "when the database is a bare directory" do
      let(:path) { Fixtures.join('mock-database-dir') }

      before { FileUtils.mkdir(path) }

      subject { described_class.new(path) }

      it "should return the mtime of the directory" do
        expect(subject.commit_id).to be(nil)
      end

      after { FileUtils.rmdir(path) }
    end
  end

  describe "#last_updated_at" do
    context "when the database is a git repository" do
      let(:last_commit) { Fixtures::Database::COMMIT }
      let(:last_commit_timestamp) do
        Dir.chdir(Fixtures::Database::PATH) do
          Time.parse(`git log -n 2 --date=iso8601 --pretty="%cd" #{last_commit}`)
        end
      end

      it "should return the timestamp of the last commit" do
        expect(subject.last_updated_at).to be == last_commit_timestamp
      end
    end

    context "when the database is a bare directory" do
      let(:path) { Fixtures.join('mock-database-dir') }

      before { FileUtils.mkdir(path) }

      subject { described_class.new(path) }

      it "should return the mtime of the directory" do
        expect(subject.last_updated_at).to be == File.mtime(path)
      end

      after { FileUtils.rmdir(path) }
    end
  end

  describe "#advisories" do
    subject { super().advisories }

    it "should return a list of all advisories." do
      expect(subject.map(&:path)).to match_array(vendored_advisories)
    end
  end

  describe "ingestion boundary" do
    let(:database_root) { Fixtures.join('ingestion-boundary-db') }
    let(:gems_root)     { File.join(database_root,'gems') }
    let(:gem_root)      { File.join(gems_root,'example_gem') }

    let(:valid_advisory) do
      <<~YAML
        ---
        gem: example_gem
        cve: 2020-0001
        url: https://example.com/advisory
        title: Example advisory
        date: 2020-01-01
        description: An example advisory.
        patched_versions:
          - ">= 2.0.0"
      YAML
    end

    before do
      FileUtils.mkdir_p(gem_root)
      File.write(File.join(gem_root,'CVE-2020-0001.yml'),valid_advisory)
    end

    after { FileUtils.rm_rf(database_root) }

    subject { described_class.new(database_root) }

    def advisory_paths
      subject.advisories.map(&:path)
    end

    describe "#initialize" do
      it "must resolve a symlinked database root to its real path" do
        link_path = Fixtures.join('ingestion-boundary-link')

        FileUtils.ln_s(database_root,link_path)

        begin
          expect(described_class.new(link_path).path).to eq(File.realpath(database_root))
        ensure
          FileUtils.rm_f(link_path)
        end
      end
    end

    context "when an advisory file is a symlink" do
      let(:outside_file) { Fixtures.join('outside-advisory.yml') }

      before do
        File.write(outside_file,valid_advisory)
        FileUtils.ln_s(outside_file,File.join(gem_root,'LINK-1.yml'))
      end

      after { FileUtils.rm_f(outside_file) }

      it "must reject the symlink instead of following it" do
        expect {
          advisory_paths
        }.to raise_error(described_class::InvalidDatabaseError, /symlink/)
      end
    end

    context "when a parent directory symlink escapes the database root" do
      let(:outside_root) { Fixtures.join('outside-gem-directory') }

      before do
        FileUtils.mkdir_p(outside_root)
        File.write(File.join(outside_root,'ESCAPE-1.yml'),valid_advisory)
        FileUtils.ln_s(outside_root,File.join(gems_root,'escaping_gem'))
      end

      after { FileUtils.rm_rf(outside_root) }

      it "must reject the entry because its real path escapes the root" do
        expect {
          advisory_paths
        }.to raise_error(described_class::InvalidDatabaseError)
      end
    end

    context "when a gem entry is a symlinked directory" do
      before do
        other_root = File.join(gems_root,'real_gem')
        FileUtils.mkdir_p(other_root)
        FileUtils.ln_s(other_root,File.join(gems_root,'evil_gem'))
      end

      it "must reject the symlinked directory" do
        expect {
          advisory_paths
        }.to raise_error(described_class::InvalidDatabaseError, /symlink/)
      end
    end

    context "when an advisory file is not a regular file" do
      before do
        File.mkfifo(File.join(gem_root,'FIFO-1.yml'))
      end

      it "must reject non-regular files" do
        expect {
          advisory_paths
        }.to raise_error(described_class::InvalidDatabaseError, /regular/)
      end
    end

    context "when an advisory file exceeds the size limit" do
      before do
        stub_const("#{described_class}::MAX_ADVISORY_SIZE",64)
      end

      it "must reject the oversized file" do
        expect {
          advisory_paths
        }.to raise_error(described_class::InvalidDatabaseError, /exceeds the limit/)
      end
    end

    context "when an advisory violates the schema" do
      before do
        File.write(File.join(gem_root,'BAD-1.yml'),"gem: example_gem\npatched_versions:\n  - \"garbage\"\n")
      end

      it "must fail closed with an InvalidAdvisoryError" do
        expect {
          advisory_paths
        }.to raise_error(described_class::InvalidAdvisoryError)
      end

      it "must not silently treat the database as empty" do
        expect {
          subject.check_gem(Gem::Specification.new { |s| s.name='example_gem'; s.version='1.0.0' }).to_a
        }.to raise_error(described_class::InvalidAdvisoryError)
      end
    end

    context "when a lookup uses an unsafe gem name" do
      it "must never read outside of the gems directory" do
        expect(subject.advisories_for('../../etc').to_a).to be_empty
        expect(subject.advisories_for('.').to_a).to be_empty
      end
    end

    context "when a primary identifier is re-declared with different ranges" do
      let(:second_advisory) do
        valid_advisory.sub('title: Example advisory',
                           'title: Duplicate primary identifier')
                     .sub('>= 2.0.0','>= 3.0.0')
      end

      before do
        # The second file declares the same primary CVE identifier as the
        # first, but claims a different patched range.
        File.write(File.join(gem_root,'CVE-2020-0001-copy.yml'),second_advisory)
      end

      it "must reject the conflicting aliases" do
        expect {
          subject.advisories_for('example_gem').to_a
        }.to raise_error(described_class::InvalidDatabaseError, /conflicting advisories/)
      end
    end

    context "when two distinct advisories merely share a secondary alias" do
      let(:second_advisory) do
        valid_advisory.sub('cve: 2020-0001','cve: 2020-0002')
                        .sub('>= 2.0.0','>= 3.0.0')
      end

      before do
        File.write(File.join(gem_root,'CVE-2020-0002.yml'),second_advisory)
      end

      it "must accept the distinct advisories even if their ranges differ" do
        expect {
          subject.advisories_for('example_gem').to_a
        }.not_to raise_error
      end
    end

    context "when two advisories share a secondary alias with identical ranges" do
      let(:second_advisory) do
        valid_advisory.sub('cve: 2020-0001',"cve: 2020-0002\nghsa: aaaa-bbbb-cccc")
      end

      before do
        first = File.join(gem_root,'CVE-2020-0001.yml')
        File.write(first,valid_advisory + "ghsa: aaaa-bbbb-cccc\n")
        File.write(File.join(gem_root,'CVE-2020-0002.yml'),second_advisory)
      end

      it "must accept the compatible duplicate alias" do
        expect {
          subject.advisories_for('example_gem').to_a
        }.not_to raise_error
      end
    end

    context "when the database is valid" do
      it "must ingest the regular advisory file" do
        paths = advisory_paths

        expect(paths).to contain_exactly(File.join(gem_root,'CVE-2020-0001.yml'))
      end

      it "must return no advisories for gems without a directory" do
        expect(subject.advisories_for('does_not_exist').to_a).to be_empty
      end

      it "must count only regular advisory files" do
        expect(subject.size).to eq(1)
      end
    end
  end

  describe "#advisories_for" do
    let(:gem) { 'activesupport' }
    let(:vendored_advisories_for) do
      Dir[File.join(Fixtures::Database::PATH, "gems/#{gem}/*.yml")].sort
    end

    subject { super().advisories_for(gem) }

    it "should return a list of all advisories." do
      expect(subject.map(&:path)).to match_array(vendored_advisories_for)
    end
  end

  describe "#check_gem" do
    let(:gem) do
      Gem::Specification.new do |s|
        s.name    = 'actionpack'
        s.version = '3.1.9'
      end
    end

    context "when given a block" do
      it "should yield every advisory effecting the gem" do
        advisories = []

        subject.check_gem(gem) do |advisory|
          advisories << advisory
        end

        expect(advisories).not_to be_empty
        expect(advisories.all? { |advisory|
          advisory.kind_of?(Bundler::Audit::Advisory)
        }).to be_truthy
      end
    end

    context "when given no block" do
      it "should return an Enumerator" do
        expect(subject.check_gem(gem)).to be_kind_of(Enumerable)
      end
    end
  end

  describe "#size" do
    it { expect(subject.size).to eq vendored_advisories.count }
  end

  describe "#to_s" do
    it "should return the Database path" do
      expect(subject.to_s).to eq(subject.path)
    end
  end

  describe "#inspect" do
    it "should produce a Ruby-ish instance descriptor" do
      expect(subject.inspect).to eq("#<#{described_class}:#{subject.path}>")
    end
  end
end
