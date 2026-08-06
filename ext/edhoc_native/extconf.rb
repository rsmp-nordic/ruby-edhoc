require "mkmf"
require "fileutils"
require "shellwords"
require_relative "build_config"

ROOT = File.expand_path("../..", __dir__)
LIBEDHOC = File.join(ROOT, "vendor", "libedhoc")
BUILD = File.join(ROOT, "build", "libedhoc-ruby")
CMAKE_PROJECT = File.join(__dir__, "cmake")
DEPENDENCY_BUILD = File.join(BUILD, "libedhoc")

def run!(*command)
  puts command.shelljoin
  abort "command failed: #{command.shelljoin}" unless system(*command)
end

def cmake_cache_value(lines, key)
  line = lines.find { |entry| entry.start_with?("#{key}:INTERNAL=") }
  line.split("=", 2).last.strip if line
end

build_config = EdhocNative::BuildConfig.new
cache = File.join(BUILD, "CMakeCache.txt")
if File.file?(cache)
  cache_lines = File.readlines(cache)
  source = cmake_cache_value(cache_lines, "CMAKE_HOME_DIRECTORY")
  generator = cmake_cache_value(cache_lines, "CMAKE_GENERATOR")
  source_changed = source && File.expand_path(source) != CMAKE_PROJECT
  generator_changed = build_config.generator && generator != build_config.generator
  FileUtils.rm_rf(BUILD) if source_changed || generator_changed
end

run!(
  "cmake", "-S", CMAKE_PROJECT, "-B", BUILD,
  *build_config.cmake_arguments,
  "-DLIBEDHOC_SOURCE=#{LIBEDHOC}",
  "-DLIBEDHOC_ENABLE_TESTS=OFF",
  "-DLIBEDHOC_BUILD_EXTERNAL_DEPS=ON",
  "-DENABLE_TESTING=OFF",
  "-DENABLE_PROGRAMS=OFF",
  "-DGEN_FILES=OFF",
  "-DCONFIG_LIBEDHOC_LOG_LEVEL=0",
  "-DCONFIG_LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID=32",
  "-DCONFIG_LIBEDHOC_CIPHER_SUITE_0_ENABLE=1",
  "-DCONFIG_LIBEDHOC_CIPHER_SUITE_2_ENABLE=0",
  "-DCONFIG_LIBEDHOC_CIPHER_SUITE_4_ENABLE=1",
  "-DCONFIG_LIBEDHOC_CIPHER_SUITE_24_ENABLE=0",
  "-DCONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE=0",
  "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
  "-DCMAKE_BUILD_TYPE=Release"
)
run!("cmake", "--build", BUILD, "--config", "Release", "--target", "libedhoc")

vendor_include = [
  File.join(LIBEDHOC, "include"),
  File.join(DEPENDENCY_BUILD, "include", "generated"),
  File.join(LIBEDHOC, "library", "internal"),
  File.join(LIBEDHOC, "library", "cipher_suites", "cipher_suite_0"),
  File.join(LIBEDHOC, "library", "cipher_suites", "cipher_suite_4"),
  File.join(LIBEDHOC, "backends", "cbor", "include"),
  File.join(LIBEDHOC, "backends", "log", "include"),
  File.join(LIBEDHOC, "externals", "zcbor", "include"),
  File.join(LIBEDHOC, "externals", "compact25519", "src"),
  File.join(LIBEDHOC, "externals", "compact25519", "src", "c25519"),
  File.join(DEPENDENCY_BUILD, "externals", "mbedtls", "tf-psa-crypto", "include"),
  File.join(LIBEDHOC, "externals", "mbedtls", "tf-psa-crypto", "include"),
  File.join(LIBEDHOC, "externals", "mbedtls", "tf-psa-crypto", "drivers", "builtin", "include"),
  File.join(LIBEDHOC, "externals", "mbedtls", "tf-psa-crypto", "drivers", "everest", "include")
]

vendor_include.each { |path| $INCFLAGS << " -I#{path.shellescape}" }

$CFLAGS << " -std=gnu11 -pthread"
$LDFLAGS << " -pthread"
$srcs = %w[
  edhoc_native.c
  edhoc_cipher_suites.c
  edhoc_cipher_suite_0.c
  edhoc_cipher_suite_4.c
]

lib_paths = [
  File.join(DEPENDENCY_BUILD, "library", "liblibedhoc.a"),
  File.join(DEPENDENCY_BUILD, "backends", "libbackend_cbor.a"),
  File.join(DEPENDENCY_BUILD, "externals", "libzcbor.a"),
  File.join(DEPENDENCY_BUILD, "externals", "libcompact25519.a"),
  File.join(DEPENDENCY_BUILD, "externals", "mbedtls", "tf-psa-crypto", "core", "libtfpsacrypto.a")
]

$LOCAL_LIBS << " " << lib_paths.map(&:shellescape).join(" ")
$LOCAL_LIBS << " -lws2_32 -lbcrypt" if RUBY_PLATFORM.include?("mingw")

create_makefile("edhoc_native")
