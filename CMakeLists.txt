cmake_minimum_required(VERSION 3.20)
project(lab3_rsa_hybrid LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(WIN32)
    set(PLATFORM_NAME "windows")
else()
    set(PLATFORM_NAME "ubuntu")
endif()

if(MSVC)
    set(COMPILER_NAME "msvc")
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    set(COMPILER_NAME "clang")
else()
    set(COMPILER_NAME "gcc")
endif()

message(STATUS "Platform: ${PLATFORM_NAME}, Compiler: ${COMPILER_NAME}")
message(STATUS "Suggested build dir: ${CMAKE_SOURCE_DIR}/build_${PLATFORM_NAME}_${COMPILER_NAME}/")

# OpenSSL configuration for MSVC, Clang, GCC on Windows and Linux
if(WIN32)
    if(MSVC)
        set(OPENSSL_ROOT_DIR "D:/UIT/NT219/libs/openssl/msvc" CACHE PATH "OpenSSL root dir" FORCE)
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        set(OPENSSL_ROOT_DIR "D:/UIT/NT219/libs/openssl/clang" CACHE PATH "OpenSSL root dir" FORCE)
    else()
        set(OPENSSL_ROOT_DIR "D:/UIT/NT219/libs/openssl/gcc" CACHE PATH "OpenSSL root dir" FORCE)
    endif()
else()
    if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
        set(OPENSSL_ROOT_DIR "$ENV{HOME}/Desktop/nt219lib/openssl/clang" CACHE PATH "OpenSSL root dir" FORCE)
    else()
        set(OPENSSL_ROOT_DIR "$ENV{HOME}/Desktop/nt219lib/openssl/gcc" CACHE PATH "OpenSSL root dir" FORCE)
    endif()
endif()

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

option(LAB3_WERROR "Treat warnings as errors (GCC/Clang)" ON)
function(lab3_set_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /permissive- /utf-8)
    else()
        target_compile_options(${target} PRIVATE -Wall -Wextra -Wpedantic)
        if(LAB3_WERROR)
            target_compile_options(${target} PRIVATE -Werror)
        endif()
    endif()
endfunction()

# ---- Targets ----
add_library(rsa_hybrid_core STATIC
    src/utils.cpp
    src/ossl_raii.cpp
    src/bn_math.cpp
    src/rsa_params.cpp
    src/key_io.cpp
    src/rsa_encoding.cpp
    src/aead.cpp
    src/package.cpp
    src/hybrid_oaep.cpp
    src/rsa_kem.cpp
    src/rsa_oaep.cpp
    src/key_manager.cpp
    src/hybrid_engine.cpp
    src/kat_runner.cpp
    src/bench.cpp
)
target_include_directories(rsa_hybrid_core PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(rsa_hybrid_core PUBLIC
    OpenSSL::Crypto OpenSSL::SSL Threads::Threads)
if(WIN32)
    target_link_libraries(rsa_hybrid_core PUBLIC ws2_32 crypt32)
endif()
lab3_set_warnings(rsa_hybrid_core)

add_executable(rsatool src/main.cpp)
target_link_libraries(rsatool PRIVATE rsa_hybrid_core)
lab3_set_warnings(rsatool)

add_executable(lab02 src/main.cpp)
target_link_libraries(lab02 PRIVATE rsa_hybrid_core)
lab3_set_warnings(lab02)

# Standalone in-class executables
add_executable(task_a task_a_bignum.cpp)
target_link_libraries(task_a PRIVATE OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(task_a PRIVATE ws2_32 crypt32)
endif()

add_executable(task_b task_b_rsa_keys.cpp)
target_link_libraries(task_b PRIVATE OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(task_b PRIVATE ws2_32 crypt32)
endif()

add_executable(task_c task_c_oaep.cpp)
target_link_libraries(task_c PRIVATE OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(task_c PRIVATE ws2_32 crypt32)
endif()

add_executable(task_d task_d_hybrid.cpp)
target_link_libraries(task_d PRIVATE OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(task_d PRIVATE ws2_32 crypt32)
endif()

add_executable(task_e task_e_kem.cpp)
target_link_libraries(task_e PRIVATE OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(task_e PRIVATE ws2_32 crypt32)
endif()

option(BUILD_TESTS "Build unit tests" ON)
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
