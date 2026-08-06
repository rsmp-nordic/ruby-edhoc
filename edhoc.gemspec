lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'edhoc/version'

Gem::Specification.new do |spec|
  spec.name = 'edhoc'
  spec.version = Edhoc::VERSION
  spec.authors = ['Emil Tin']
  spec.email = ['zf0f@kk.dk']

  spec.summary = 'Complete EDHOC protocol bindings for Ruby using libedhoc built-in crypto.'
  spec.description = 'Ruby bindings for EDHOC methods 0-3 and cipher suites 0, 2, 4, and 24, ' \
                     'including credentials, EAD, exporters, OSCORE, and CoAP helpers.'
  spec.homepage = 'https://github.com/rsmp-nordic/ruby-edhoc'
  spec.licenses = ['MIT']
  spec.required_ruby_version = '>= 3.4'

  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = 'https://github.com/rsmp-nordic/ruby-edhoc/tree/main'
  spec.metadata['bug_tracker_uri'] = 'https://github.com/rsmp-nordic/ruby-edhoc/issues'
  spec.metadata['rubygems_mfa_required'] = 'true'

  spec.files = Dir[
    'README.md',
    'LIBEDHOC_FINDINGS.md',
    'LICENSE.txt',
    'lib/**/*.rb',
    'ext/**/*.{c,h,rb}',
    'ext/edhoc_native/cmake/CMakeLists.txt',
    'vendor/libedhoc/**/*',
    'vendor/libedhoc/.gitmodules',
    'patches/libedhoc/*.patch'
  ]
  spec.extensions = ['ext/edhoc_native/extconf.rb']
  spec.require_paths = ['lib']
end
