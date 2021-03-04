find_package(MSPGCC REQUIRED)
include(AddObject)

include(UseMSPGCC)
add_object(sm_entry.o sm_entry.s)
add_object(sm_isr.o sm_isr.s)
add_object(sm_isr_basic.o sm_isr_basic.s)
add_object(sm_isr_dummy.o sm_isr_dummy.s)
add_object(sm_exit.o sm_exit.s)
add_object(sm_verify.o sm_verify.s)
add_object(sm_mmio_entry.o sm_mmio_entry.s)
add_object(sm_mmio_exclusive.o sm_mmio_entry.s
           -Xassembler --defsym -Xassembler mmio_exclusive=1)

add_object(sm_mulhi3.o sm_mulhi3.s)
add_object(sm_udivhi3.o sm_udivhi3.s)
add_object(sm_divhi3.o sm_divhi3.s)
add_object(sm_modhi3.o sm_modhi3.s)
add_object(sm_umodhi3.o sm_umodhi3.s)

include(UseSancusCC)
set(EXTRA_FLAGS -I${CMAKE_SOURCE_DIR}/src/sancus_support)
add_object(sm_output.o sm_output.c ${EXTRA_FLAGS})
add_object(sm_input.o sm_input.c ${EXTRA_FLAGS})
add_object(sm_set_key.o sm_set_key.c ${EXTRA_FLAGS})

set(STUBS
    ${CMAKE_CURRENT_BINARY_DIR}/sm_entry.o
    ${CMAKE_CURRENT_BINARY_DIR}/sm_isr.o
    ${CMAKE_CURRENT_BINARY_DIR}/sm_isr_basic.o
    ${CMAKE_CURRENT_BINARY_DIR}/sm_isr_dummy.o
    ${CMAKE_CURRENT_BINARY_DIR}/sm_exit.o
    ${CMAKE_CURRENT_BINARY_DIR}/sm_verify.o
    ${CMAKE_CURRENT_BINARY_DIR}/sm_output.o
    ${CMAKE_CURRENT_BINARY_DIR}/sm_input.o
    ${CMAKE_CURRENT_BINARY_DIR}/sm_set_key.o
    ${CMAKE_CURRENT_BINARY_DIR}/sm_mmio_entry.o
    ${CMAKE_CURRENT_BINARY_DIR}/sm_mmio_exclusive.o

    ${CMAKE_CURRENT_BINARY_DIR}/sm_mulhi3.o
    ${CMAKE_CURRENT_BINARY_DIR}/sm_divhi3.o
    ${CMAKE_CURRENT_BINARY_DIR}/sm_udivhi3.o
    ${CMAKE_CURRENT_BINARY_DIR}/sm_modhi3.o
    ${CMAKE_CURRENT_BINARY_DIR}/sm_umodhi3.o
)

install(FILES ${STUBS}
        DESTINATION ${INSTALL_BASE_DIR})
