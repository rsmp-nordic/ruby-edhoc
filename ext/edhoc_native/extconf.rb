require "mkmf"
require "shellwords"

ROOT = File.expand_path("../..", __dir__)
LIBEDHOC = File.join(ROOT, "vendor", "libedhoc")
BUILD = File.join(ROOT, "build", "libedhoc-ruby")

def run!(cmd)
  puts cmd
  abort "command failed: #{cmd}" unless system(cmd)
end

run! "cmake -S #{LIBEDHOC.shellescape} -B #{BUILD.shellescape} " \
     "-DLIBEDHOC_ENABLE_TESTS=OFF " \
     "-DLIBEDHOC_BUILD_EXTERNAL_DEPS=ON " \
     "-DENABLE_TESTING=OFF " \
     "-DENABLE_PROGRAMS=OFF " \
     "-DCONFIG_LIBEDHOC_LOG_LEVEL=0 " \
     "-DCMAKE_BUILD_TYPE=Release"
run! "cmake --build #{BUILD.shellescape} --config Release --target libedhoc"

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
