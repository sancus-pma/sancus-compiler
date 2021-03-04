include(PythonConfig)
find_python_module(elftools)

configure_file(sancus/config.py.in
               ${CMAKE_CURRENT_SOURCE_DIR}/sancus/config.py @ONLY)
configure_file(sancus-cc.in sancus-cc @ONLY)
configure_file(sancus-ld.in sancus-ld @ONLY)
configure_file(sancus-crypto.in sancus-crypto @ONLY)

set(PROGS
    ${CMAKE_CURRENT_BINARY_DIR}/sancus-cc
    ${CMAKE_CURRENT_BINARY_DIR}/sancus-ld
    ${CMAKE_CURRENT_BINARY_DIR}/sancus-crypto
)

install(PROGRAMS ${PROGS} DESTINATION bin)

set(FILES
    msp430.x
    memory.x
    periph.x
    sancus.ld
)

set(PY_FILES
    compiler.py
    linker.py
    common.py
)

set(PY_LIBS
    sancus/__init__.py
    sancus/crypto.py
    sancus/paths.py
    sancus/config.py
    sancus/sancus_config.py
)

install(FILES ${FILES}    DESTINATION ${INSTALL_BASE_DIR})
install(FILES ${PY_FILES} DESTINATION ${INSTALL_PYTHON_DIR})
install(FILES ${PY_LIBS}  DESTINATION ${INSTALL_PYTHON_LIBS_DIR}/sancus)
