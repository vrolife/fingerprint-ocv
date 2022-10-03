cmake_minimum_required(VERSION 3.13)
project(fingerprint-ocv)

include(CTest)

find_package(PkgConfig REQUIRED)

set(JINX_NO_TESTS ON)
set(JINX_NO_INSTALL ON)
set(JINX_NO_EXAMPLES ON)
set(JINX_BUILD_DBUS ON)
set(JINX_BUILD_USB ON)
set(JINX_BUILD_OPENSSL ON)
add_subdirectory(libs/jinx)
add_subdirectory(libs/asyncusb)
add_subdirectory(libs/asyncdbus)
add_subdirectory(src)
