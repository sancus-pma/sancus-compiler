include(CompilerConfig)

configure_file(config.h.in config.h)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(SRC
    crypto.cpp
    spongent.cpp
)

add_library(sancus-crypto SHARED ${SRC})

install(TARGETS sancus-crypto
        LIBRARY DESTINATION ${INSTALL_BASE_DIR})
