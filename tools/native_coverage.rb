# Measures only the extension-owned C source, excluding vendored libedhoc.
module NativeCoverage
  extend Rake::FileUtilsExt

  ROOT = File.expand_path('..', __dir__)
  COVERAGE_DIR = File.join(ROOT, 'coverage/native')
  SOURCE = File.join(ROOT, 'ext/edhoc_native/edhoc_native.c')
  MINIMUMS = { 'functions' => 100.0, 'lines' => 95.0, 'branches' => 75.0 }.freeze

  module_function

  def run
    rebuild_and_test
    profile = merge_profiles
    output = report(profile)
    enforce_thresholds(output)
  end

  def rebuild_and_test
    FileUtils.rm_rf(COVERAGE_DIR)
    FileUtils.mkdir_p(COVERAGE_DIR)
    sh({ 'EDHOC_NATIVE_COVERAGE' => 'true' }, 'bundle exec rake clean compile')
    sh({ 'LLVM_PROFILE_FILE' => File.join(COVERAGE_DIR, 'edhoc-%p.profraw') }, 'bundle exec sus')
  end

  def merge_profiles
    raw_profiles = Dir.glob(File.join(COVERAGE_DIR, '*.profraw'))
    abort 'Native coverage did not produce an LLVM raw profile' if raw_profiles.empty?

    profile = File.join(COVERAGE_DIR, 'edhoc.profdata')
    sh(*llvm_tool('profdata'), 'merge', '-sparse', *raw_profiles, '-o', profile)
    profile
  end

  def report(profile)
    command = [*llvm_tool('cov'), 'report', extension, "-instr-profile=#{profile}", SOURCE]
    stdout, stderr, status = Open3.capture3(*command)
    puts stdout
    warn stderr unless stderr.empty?
    abort "Native coverage report failed: #{command.shelljoin}" unless status.success?

    stdout
  end

  def extension
    result = Dir.glob(File.join(ROOT, 'tmp', '**', 'edhoc_native.{bundle,so}')).find do |path|
      !path.include?('/stage/') && !path.include?('.dSYM/')
    end
    abort 'Could not locate the instrumented edhoc_native extension' unless result

    result
  end

  def enforce_thresholds(output)
    fields = output.lines.find { |line| line.start_with?('TOTAL') }&.split
    abort 'Could not parse native coverage summary' unless fields&.length.to_i >= 13

    actual = { 'functions' => percent(fields, 6), 'lines' => percent(fields, 9),
               'branches' => percent(fields, 12) }
    failures = MINIMUMS.filter_map do |name, required|
      "#{name} #{actual.fetch(name)}% < #{required}%" if actual.fetch(name) < required
    end
    abort "Native coverage is below the required thresholds: #{failures.join(', ')}" unless failures.empty?
  end

  def percent(fields, index) = fields.fetch(index).delete_suffix('%').to_f

  def llvm_tool(component)
    override = ENV.fetch("LLVM_#{component.upcase}", nil)
    return Shellwords.split(override) if override
    return ['xcrun', "llvm-#{component}"] if RUBY_PLATFORM.include?('darwin')

    ["llvm-#{component}"]
  end
end
