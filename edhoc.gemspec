lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'edhoc/version'

Gem::Specification.new do |spec|
  spec.name = 'edhoc'
  spec.version = Edhoc::VERSION
  spec.authors = ['Emil Tin']
  spec.email = ['zf0f@kk.dk']

  spec.summary = 'Experimental Ruby bindings for EDHOC using libedhoc.'
  spec.description = 'A narrow Ruby wrapper around libedhoc for EDHOC method 0 / cipher suites 0 and 4, ' \
                     'built for Secure RSMP prototype and conformance tooling.'
  spec.homepage = 'https://github.com/rsmp-nordic/ruby-edhoc'
  spec.licenses = ['MIT']
  spec.required_ruby_version = '>= 3.4'

  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = 'https://github.com/rsmp-nordic/ruby-edhoc/tree/main'
  spec.metadata['bug_tracker_uri'] = 'https://github.com/rsmp-nordic/ruby-edhoc/issues'
  spec.metadata['rubygems_mfa_required'] = 'true'

  spec.files = Dir[
    'README.md',
    'LICENSE.txt',
    'lib/**/*.rb',
    'ext/**/*.{c,h,rb}',
    'ext/edhoc_native/cmake/CMakeLists.txt',
    'vendor/libedhoc/**/*',
    'vendor/libedhoc/.gitmodules'
  ]
  spec.extensions = ['ext/edhoc_native/extconf.rb']
  spec.require_paths = ['lib']
end
