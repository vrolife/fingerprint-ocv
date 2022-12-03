set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set_target_properties(jinx PROPERTIES CXX_VISIBILITY_PRESET hidden)

# manager
add_library(manager STATIC manager.cpp)
target_include_directories(manager PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(manager PUBLIC jinx jinx::usb jinx::dbus)

# cvext
if (DEFINED ENV{OPENCV_SDK_HOME})
set(OpenCV_DIR $ENV{OPENCV_SDK_HOME}/lib/cmake/opencv4)
endif()

set(OpenCV_DIR "${CMAKE_CURRENT_BINARY_DIR}/vcpkg_installed/x64-linux/share/opencv4")
find_package(OpenCV REQUIRED)

add_library(cvext STATIC cvext.cpp)
target_include_directories(cvext PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(cvext PUBLIC opencv_core opencv_imgproc opencv_features2d opencv_imgcodecs opencv_calib3d opencv_flann)

if (CMAKE_BUILD_TYPE STREQUAL Debug)
target_link_libraries(cvext PUBLIC opencv_highgui)
endif()

# driver
add_subdirectory(drv_fpc)

# main
add_executable(fingerprint-ocv main.cpp)
target_link_libraries(fingerprint-ocv PRIVATE 
    jinx
    jinx::openssl
    cvext
    manager
    $<TARGET_OBJECTS:fpc9201>
)
set_target_properties(fingerprint-ocv PROPERTIES CXX_VISIBILITY_PRESET hidden)

install(TARGETS fingerprint-ocv)
