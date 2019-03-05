cmake_minimum_required (VERSION 2.8)
project (planeDB)


list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

find_package (DPDK REQUIRED)

set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mssse3 -Wall -Wextra -Wno-unused-parameter -O0 -ggdb -g")

set (LINK_LIBS ${LINK_LIBS} ${DPDK_LIBRARIES} m rt)
cmake_minimum_required (VERSION 2.8)
project (planeDB)


list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/")

include_directories(${DPDK_INCLUDE_DIR})

aux_source_directory (src SRCS)
foreach(p ${SRCS})
	get_filename_component(target "${p}" NAME_WE)
	add_executable(${target} ${p})
    target_link_libraries(${target}
    ${LINK_LIBS}
	)
	set_target_properties (${target} PROPERTIES COMPILE_FLAGS ${CMAKE_CXX_FLAGS})
endforeach(p)
