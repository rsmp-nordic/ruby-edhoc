Gem::Specification.new do |spec|
  spec.name = "edhoc"
  spec.version = "0.1.0"
  spec.authors = ["RSMP"]
  spec.email = ["rsmp@example.invalid"]

  spec.summary = "Experimental Ruby bindings for EDHOC using libedhoc"
  spec.description = "A first Ruby wrapper around libedhoc for EDHOC method 0 / cipher suite 0."
  spec.homepage = "https://github.com/kamil-kielbasa/libedhoc"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2"

  spec.files = Dir[
    "README.md",
    "LICENSE.txt",
    "lib/**/*.rb",
    "ext/**/*.{c,h,rb}",
    "vendor/libedhoc/include/**/*",
    "vendor/libedhoc/library/**/*",
    "vendor/libedhoc/backends/**/*",
    "vendor/libedhoc/helpers/**/*",
    "vendor/libedhoc/tests/include/**/*",
    "vendor/libedhoc/cmake/**/*",
    "vendor/libedhoc/CMakeLists.txt",
    "vendor/libedhoc/externals/zcbor/**/*",
    "vendor/libedhoc/externals/compact25519/**/*",
    "vendor/libedhoc/externals/mbedtls/**/*",
    "vendor/libedhoc/externals/Unity/**/*"
  ]
  spec.extensions = ["ext/edhoc_native/extconf.rb"]
  spec.require_paths = ["lib"]

  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rake-compiler", "~> 1.2"
  spec.add_development_dependency "sus", "~> 0.36"
end
