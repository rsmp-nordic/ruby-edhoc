cmake_minimum_required(VERSION 3.21)
project(ruby_edhoc_dependencies LANGUAGES C)

if(NOT LIBEDHOC_SOURCE)
    message(FATAL_ERROR "LIBEDHOC_SOURCE must point to the vendored libedhoc tree")
endif()

# Build libedhoc as a dependency. This retains its strict warning set while
# avoiding top-level-only development warnings tied to a specific Clang SDK.
add_subdirectory("${LIBEDHOC_SOURCE}" libedhoc)
