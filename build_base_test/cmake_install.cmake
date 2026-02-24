# Install script for directory: /home/xinyi/Workspace/NanoMQ_mirror

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set default install directory permissions.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/usr/bin/objdump")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/etc/nanomq.conf;/usr/local/etc/nanomq_acl.conf;/usr/local/etc/nanomq_bridge.conf;/usr/local/etc/nanomq_dds_gateway.conf;/usr/local/etc/nanomq_ee.conf;/usr/local/etc/nanomq_ee_win.conf;/usr/local/etc/nanomq_example.conf;/usr/local/etc/nanomq_gee_8155c_all.conf;/usr/local/etc/nanomq_gee_8155c_all_android.conf;/usr/local/etc/nanomq_gee_8295c_90.conf;/usr/local/etc/nanomq_gee_8295c_90_android.conf;/usr/local/etc/nanomq_gee_8295c_92.conf;/usr/local/etc/nanomq_gee_8295c_92_android.conf;/usr/local/etc/nanomq_gee_e02c_P658.conf;/usr/local/etc/nanomq_gee_e02c_P658_android.conf;/usr/local/etc/nanomq_gee_e02c_all.conf;/usr/local/etc/nanomq_gee_e02c_all_android.conf;/usr/local/etc/nanomq_gee_e04c_87.conf;/usr/local/etc/nanomq_gee_e04c_87_android.conf;/usr/local/etc/nanomq_gee_e04c_91.conf;/usr/local/etc/nanomq_gee_e04c_91_android.conf;/usr/local/etc/nanomq_gee_e04c_E4.conf;/usr/local/etc/nanomq_gee_e04c_E4_android.conf;/usr/local/etc/nanomq_gee_e04g_E7.conf;/usr/local/etc/nanomq_gee_e04g_E7_android.conf;/usr/local/etc/nanomq_gee_e04g_all.conf;/usr/local/etc/nanomq_gee_e04g_all_android.conf;/usr/local/etc/nanomq_geely.conf;/usr/local/etc/nanomq_geely_android.conf;/usr/local/etc/nanomq_old.conf;/usr/local/etc/nanomq_pwd.conf;/usr/local/etc/nanomq_sdv.conf;/usr/local/etc/nanomq_sdv_android.conf;/usr/local/etc/nanomq_seres.conf;/usr/local/etc/nanomq_seres_android.conf;/usr/local/etc/nanomq_vsomeip_gateway.conf;/usr/local/etc/nanomq_zmq_gateway.conf")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/etc" TYPE FILE FILES
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_acl.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_bridge.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_dds_gateway.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_ee.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_ee_win.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_example.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_gee_8155c_all.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_gee_8155c_all_android.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_gee_8295c_90.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_gee_8295c_90_android.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_gee_8295c_92.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_gee_8295c_92_android.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_gee_e02c_P658.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_gee_e02c_P658_android.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_gee_e02c_all.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_gee_e02c_all_android.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_gee_e04c_87.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_gee_e04c_87_android.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_gee_e04c_91.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_gee_e04c_91_android.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_gee_e04c_E4.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_gee_e04c_E4_android.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_gee_e04g_E7.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_gee_e04g_E7_android.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_gee_e04g_all.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_gee_e04g_all_android.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_geely.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_geely_android.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_old.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_pwd.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_sdv.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_sdv_android.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_seres.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_seres_android.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_vsomeip_gateway.conf"
    "/home/xinyi/Workspace/NanoMQ_mirror/etc/nanomq_zmq_gateway.conf"
    )
endif()

if(NOT CMAKE_INSTALL_LOCAL_ONLY)
  # Include the install script for each subdirectory.
  include("/home/xinyi/Workspace/NanoMQ_mirror/build_base_test/nng/cmake_install.cmake")
  include("/home/xinyi/Workspace/NanoMQ_mirror/build_base_test/nanomq/cmake_install.cmake")

endif()

if(CMAKE_INSTALL_COMPONENT)
  set(CMAKE_INSTALL_MANIFEST "install_manifest_${CMAKE_INSTALL_COMPONENT}.txt")
else()
  set(CMAKE_INSTALL_MANIFEST "install_manifest.txt")
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
file(WRITE "/home/xinyi/Workspace/NanoMQ_mirror/build_base_test/${CMAKE_INSTALL_MANIFEST}"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
