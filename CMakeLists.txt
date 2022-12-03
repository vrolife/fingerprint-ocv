cmake_minimum_required(VERSION 3.13)

set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_SOURCE_DIR}/vcpkg/scripts/buildsystems/vcpkg.cmake)
set(LIBEVENT_FIND_PACKAGE ON)
set(DBUS_FIND_PACKAGE ON)

project(fingerprint-ocv)

include(CTest)

find_package(PkgConfig REQUIRED)

set(JINX_NO_TESTS ON)
set(JINX_NO_INSTALL ON)
set(JINX_NO_EXAMPLES ON)
set(JINX_BUILD_DBUS ON)
set(JINX_BUILD_USB ON)
set(JINX_BUILD_OPENSSL ON)
add_subdirectory(jinx)
add_subdirectory(asyncusb)
add_subdirectory(asyncdbus)
add_subdirectory(src)
