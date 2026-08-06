cmake_minimum_required(VERSION 3.21)
project(ruby_edhoc_dependencies LANGUAGES C)

if(NOT LIBEDHOC_SOURCE)
    message(FATAL_ERROR "LIBEDHOC_SOURCE must point to the vendored libedhoc tree")
endif()

# Mbed TLS development checkouts omit generated TF-PSA sources. ruby-edhoc
# generates and ships them when libedhoc is vendored, so installing the gem
# does not need Python packages or network access.
set(TF_PSA_GENERATED_SOURCE_DIR
    "${CMAKE_CURRENT_LIST_DIR}/../generated/tf_psa_crypto")
set(TF_PSA_GENERATED_BINARY_DIR
    "${CMAKE_CURRENT_BINARY_DIR}/libedhoc/externals/mbedtls/tf-psa-crypto/core")
set(TF_PSA_GENERATED_FILES
    psa_crypto_driver_wrappers.h
    psa_crypto_driver_wrappers_no_static.c
    tf_psa_crypto_config_check_before.h
    tf_psa_crypto_config_check_final.h
    tf_psa_crypto_config_check_user.h)
set(MBEDTLS_GENERATED_SOURCE_DIR
    "${CMAKE_CURRENT_LIST_DIR}/../generated/mbedtls")
set(MBEDTLS_GENERATED_BINARY_DIR
    "${CMAKE_CURRENT_BINARY_DIR}/libedhoc/externals/mbedtls/library")
set(MBEDTLS_GENERATED_FILES
    error.c
    ssl_debug_helpers_generated.c
    version_features.c)

file(MAKE_DIRECTORY "${TF_PSA_GENERATED_BINARY_DIR}")
foreach(generated_file IN LISTS TF_PSA_GENERATED_FILES)
    set(generated_source "${TF_PSA_GENERATED_SOURCE_DIR}/${generated_file}")
    if(NOT EXISTS "${generated_source}")
        message(FATAL_ERROR
            "Missing packaged TF-PSA source ${generated_source}; run vendor:update")
    endif()
    configure_file(
        "${generated_source}"
        "${TF_PSA_GENERATED_BINARY_DIR}/${generated_file}"
        COPYONLY)
endforeach()

file(MAKE_DIRECTORY "${MBEDTLS_GENERATED_BINARY_DIR}")
foreach(generated_file IN LISTS MBEDTLS_GENERATED_FILES)
    set(generated_source "${MBEDTLS_GENERATED_SOURCE_DIR}/${generated_file}")
    if(NOT EXISTS "${generated_source}")
        message(FATAL_ERROR
            "Missing packaged Mbed TLS source ${generated_source}; run vendor:update")
    endif()
    configure_file(
        "${generated_source}"
        "${MBEDTLS_GENERATED_BINARY_DIR}/${generated_file}"
        COPYONLY)
endforeach()

# Build libedhoc as a dependency. This retains its strict warning set while
# avoiding top-level-only development warnings tied to a specific Clang SDK.
add_subdirectory("${LIBEDHOC_SOURCE}" libedhoc)
