cmake_minimum_required(VERSION 3.22.1)

if (ANDROID_ABI STREQUAL "riscv64")
    set(ANDROID_PLATFORM "android-35")
endif ()

project("test")

add_library(test_lib SHARED test_lib.cpp)

add_library(test SHARED test.cpp)
target_link_libraries(test PUBLIC log test_lib)

add_library(test-jni-err SHARED test_jni_err.cpp)

add_library(test-jni-bad SHARED test_jni_bad.cpp)

add_library(test-nojni SHARED test_nojni.cpp)
target_link_libraries(test-nojni PUBLIC log)
