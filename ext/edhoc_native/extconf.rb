require "mkmf"
require "fileutils"
require "shellwords"
require_relative "build_config"

ROOT = File.expand_path("../..", __dir__)
LIBEDHOC = File.join(ROOT, "vendor", "libedhoc")
BUILD = File.join(ROOT, "build", "libedhoc-ruby")

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
  source_changed = source && File.expand_path(source) != LIBEDHOC
  generator_changed = build_config.generator && generator != build_config.generator
  FileUtils.rm_rf(BUILD) if source_changed || generator_changed
end

run!(
  "cmake", "-S", LIBEDHOC, "-B", BUILD,
  *build_config.cmake_arguments,
  "-DLIBEDHOC_ENABLE_TESTS=OFF",
  "-DLIBEDHOC_BUILD_EXTERNAL_DEPS=ON",
  "-DENABLE_TESTING=OFF",
  "-DENABLE_PROGRAMS=OFF",
  "-DCONFIG_LIBEDHOC_LOG_LEVEL=0",
  "-DCONFIG_LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID=64",
  "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
  "-DCMAKE_BUILD_TYPE=Release"
)
run!("cmake", "--build", BUILD, "--config", "Release", "--target", "libedhoc")

vendor_include = [
  File.join(LIBEDHOC, "include"),
  File.join(BUILD, "include", "generated"),
  File.join(LIBEDHOC, "helpers", "include"),
  File.join(LIBEDHOC, "backends", "cbor", "include"),
  File.join(LIBEDHOC, "backends", "log", "include"),
  File.join(LIBEDHOC, "externals", "zcbor", "include"),
  File.join(LIBEDHOC, "externals", "compact25519", "src"),
  File.join(LIBEDHOC, "externals", "mbedtls", "include"),
  File.join(LIBEDHOC, "externals", "mbedtls", "library"),
  File.join(LIBEDHOC, "externals", "mbedtls", "3rdparty", "everest", "include")
]

vendor_include.each { |path| $INCFLAGS << " -I#{path.shellescape}" }

$CFLAGS << " -std=gnu11"
$srcs = ["edhoc_native.c"]

lib_paths = [
  File.join(BUILD, "library", "liblibedhoc.a"),
  File.join(BUILD, "backends", "libbackend_cbor.a"),
  File.join(BUILD, "externals", "libzcbor.a"),
  File.join(BUILD, "externals", "libcompact25519.a"),
  File.join(BUILD, "externals", "mbedtls", "library", "libmbedcrypto.a")
]

$LOCAL_LIBS << " " << lib_paths.map(&:shellescape).join(" ")

create_makefile("edhoc_native")
