require 'bundler/gem_tasks'
require 'fileutils'
require 'open3'
require 'rake/extensiontask'
require 'shellwords'
require 'tmpdir'
require 'yaml'

Rake::ExtensionTask.new('edhoc_native')

task :test do
  sh 'bundle exec sus'
end

task default: %i[compile test]

# Maintains the vendored libedhoc checkout used by the native extension.
module VendorLibedhoc
  ROOT = File.expand_path(__dir__)
  VENDOR_DIR = File.join(ROOT, 'vendor/libedhoc')
  METADATA_PATH = File.join(VENDOR_DIR, 'ruby-edhoc-vendor.yml')
  REMOTE_URL = 'https://github.com/kamil-kielbasa/libedhoc.git'.freeze
  DEFAULT_REF = 'main'.freeze
  REQUIRED_EXTERNALS = %w[
    externals/mbedtls
    externals/zcbor
    externals/compact25519
    externals/Unity
  ].freeze

  module_function

  def update(ref = nil)
    ref = normalize_ref(ref)
    ensure_clean_worktree!

    Dir.mktmpdir('ruby-edhoc-libedhoc-') do |tmpdir|
      checkout = checkout_upstream(tmpdir, ref)
      commit = run('git', '-C', checkout, 'rev-parse', 'HEAD').strip
      metadata = metadata_for(checkout, ref, commit)

      copy_checkout(checkout)
      File.write(METADATA_PATH, metadata.to_yaml)
      ensure_no_git_metadata!

      puts "Vendored libedhoc #{commit} from #{ref}"
      puts "Updated #{METADATA_PATH.sub("#{ROOT}/", '')}"
    end
  end

  def normalize_ref(ref)
    value = ref.to_s.strip
    return value unless value.empty?

    metadata_ref || DEFAULT_REF
  end

  def metadata_ref
    return unless File.file?(METADATA_PATH)

    metadata = YAML.load_file(METADATA_PATH)
    ref = metadata.dig('libedhoc', 'ref')
    ref if ref.is_a?(String) && !ref.empty?
  end

  def checkout_upstream(tmpdir, ref)
    checkout = File.join(tmpdir, 'libedhoc')

    run!('git', 'clone', '--no-checkout', '--filter=blob:none', REMOTE_URL, checkout)
    fetch_ref!(checkout, ref)
    run!('git', '-C', checkout, 'checkout', '--detach', 'FETCH_HEAD')
    run!('git', '-C', checkout, 'submodule', 'update', '--init', '--depth', '1', '--jobs', '4',
         *REQUIRED_EXTERNALS)

    checkout
  end

  def fetch_ref!(checkout, ref)
    command = ['git', '-C', checkout, 'fetch', '--depth', '1', 'origin', ref]
    puts "+ #{command.shelljoin}"

    stdout, stderr, status = Open3.capture3(*command)
    puts stdout unless stdout.empty?
    warn stderr unless stderr.empty?
    return if status.success?

    abort "Could not fetch libedhoc ref #{ref.inspect}; vendored files and metadata were not updated.\n" \
          "Command failed: #{command.shelljoin}"
  end

  def copy_checkout(checkout)
    FileUtils.mkdir_p(VENDOR_DIR)
    run!('rsync', '-a', '--delete', '--exclude', '.git', "#{checkout}/", "#{VENDOR_DIR}/")
  end

  def metadata_for(checkout, ref, commit)
    {
      'libedhoc' => {
        'remote' => REMOTE_URL,
        'ref' => ref,
        'commit' => commit
      },
      'externals' => submodule_metadata(checkout)
    }
  end

  def submodule_metadata(checkout)
    urls_by_path = submodule_urls_by_path(checkout)

    run('git', '-C', checkout, 'submodule', 'status', '--recursive').each_line.with_object({}) do |line, externals|
      match = line.match(/\A(?<state>[ +-U])(?<commit>[0-9a-f]{40})\s+(?<path>\S+)/)
      next unless match

      path = match[:path]
      next unless REQUIRED_EXTERNALS.include?(path)

      name = path.sub(%r{\Aexternals/}, '')
      entry = {
        'path' => path,
        'commit' => match[:commit]
      }
      entry['remote'] = urls_by_path[path] if urls_by_path.key?(path)
      entry['state'] = match[:state] unless match[:state] == ' '
      externals[name] = entry
    end
  end

  def submodule_urls_by_path(checkout)
    output = run('git', '-C', checkout, 'config', '-f', '.gitmodules', '--get-regexp',
                 '^submodule\\..*\\.(path|url)$')
    modules = submodule_config(output)

    modules.each_value.with_object({}) do |submodule, urls|
      urls[submodule['path']] = submodule['url'] if submodule['path'] && submodule['url']
    end
  end

  def submodule_config(output)
    output.each_line.with_object({}) do |line, modules|
      key, value = line.strip.split(/\s+/, 2)
      match = key.match(/\Asubmodule\.(?<name>.+)\.(?<field>path|url)\z/)
      next unless match

      modules[match[:name]] ||= {}
      modules[match[:name]][match[:field]] = value
    end
  end

  def ensure_clean_worktree!
    return if run('git', 'status', '--porcelain').empty?

    abort 'Refusing to update vendored libedhoc with uncommitted changes present.'
  end

  def ensure_no_git_metadata!
    git_metadata = Dir.glob(File.join(VENDOR_DIR, '**/.git'), File::FNM_DOTMATCH)
    return if git_metadata.empty?

    abort "Vendored libedhoc contains Git metadata:\n#{git_metadata.join("\n")}"
  end

  def run(*command)
    stdout, stderr, status = Open3.capture3(*command)
    return stdout if status.success?

    abort "Command failed: #{command.shelljoin}\n#{stdout}#{stderr}"
  end

  def run!(*command)
    puts "+ #{command.shelljoin}"
    return if system(*command)

    abort "Command failed: #{command.shelljoin}"
  end
end

namespace :vendor do
  desc 'Update vendored libedhoc and its externals; pass [ref] to use a branch, tag, or commit'
  task :update, [:ref] do |_task, args|
    VendorLibedhoc.update(args[:ref])
  end

  namespace :libedhoc do
    desc 'Alias for vendor:update'
    task :update, [:ref] do |_task, args|
      Rake::Task['vendor:update'].invoke(args[:ref])
    end
  end
end
