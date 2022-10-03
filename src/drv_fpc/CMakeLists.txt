
if (APPLE)
set(OPENSSL_ROOT_DIR /usr/local/opt/openssl)
endif(APPLE)

find_package(OpenSSL REQUIRED)

add_library(fpc9201 STATIC crypto.cpp fpc9201.cpp fpcbio.cpp fingerprint.cpp)
target_link_libraries(fpc9201 PUBLIC jinx manager cvext OpenSSL::SSL OpenSSL::Crypto jinx::usb jinx::dbus jinx::openssl)

if (CMAKE_BUILD_TYPE STREQUAL Debug)
target_compile_definitions(fpc9201 PRIVATE -DUSE_HIGHGUI=1)
endif()
