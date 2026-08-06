require 'coverage'

Coverage.start(lines: true, branches: true) unless Coverage.running?

# Collects and enforces coverage for the public Ruby implementation.
module TestCoverage
  ROOT = File.expand_path('../lib/', __dir__)
  MINIMUM_LINE_PERCENT = 95.0
  MINIMUM_BRANCH_PERCENT = 90.0

  module_function

  def report
    totals = coverage_totals
    line_percent = percentage(*totals.fetch(:lines))
    branch_percent = percentage(*totals.fetch(:branches))
    report_summary(totals, line_percent, branch_percent)
    enforce_thresholds(line_percent, branch_percent)
  end

  def coverage_totals
    files = Coverage.result.select { |path, _data| path.start_with?(ROOT) && path.end_with?('.rb') }
    files.each_with_object({ lines: [0, 0], branches: [0, 0] }) do |(path, data), result|
      lines, branches = coverage_counts(data)
      add_counts(result.fetch(:lines), lines)
      add_counts(result.fetch(:branches), branches)
      report_file(path, lines, branches) if ENV['COVERAGE_VERBOSE'] == 'true'
    end
  end

  def coverage_counts(data)
    [data.fetch(:lines).compact, data.fetch(:branches).values.flat_map(&:values)]
  end

  def add_counts(total, counts)
    total[0] += counts.count(&:positive?)
    total[1] += counts.length
  end

  def report_summary(totals, line_percent, branch_percent)
    puts format(
      'Coverage: lines %<line_covered>d/%<line_total>d (%<line_percent>.2f%%), ' \
      'branches %<branch_covered>d/%<branch_total>d (%<branch_percent>.2f%%)',
      line_covered: totals.fetch(:lines).fetch(0), line_total: totals.fetch(:lines).fetch(1),
      line_percent: line_percent, branch_covered: totals.fetch(:branches).fetch(0),
      branch_total: totals.fetch(:branches).fetch(1), branch_percent: branch_percent
    )
  end

  def enforce_thresholds(line_percent, branch_percent)
    return if line_percent >= MINIMUM_LINE_PERCENT && branch_percent >= MINIMUM_BRANCH_PERCENT

    warn format(
      'Coverage is below the required %<lines>.2f%% lines and %<branches>.2f%% branches',
      lines: MINIMUM_LINE_PERCENT, branches: MINIMUM_BRANCH_PERCENT
    )
    exit(false)
  end

  def report_file(path, lines, branches)
    puts format(
      '  %<path>-32s lines %<lines>6.2f%% branches %<branches>6.2f%%',
      path: path.delete_prefix(ROOT), lines: percentage(lines.count(&:positive?), lines.length),
      branches: percentage(branches.count(&:positive?), branches.length)
    )
  end

  def percentage(covered, total)
    return 100.0 if total.zero?

    covered.fdiv(total) * 100
  end
end

at_exit { TestCoverage.report }
