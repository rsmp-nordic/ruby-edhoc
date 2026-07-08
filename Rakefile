require 'bundler/gem_tasks'
require 'rake/extensiontask'

Rake::ExtensionTask.new('edhoc_native')

task :test do
  sh 'bundle exec sus'
end

task default: %i[compile test]
