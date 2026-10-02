set(SECP256K1_ENABLE_MODULE_RECOVERY ON CACHE BOOL "Enable ECDSA recovery module")
add_subdirectory(secp256k1)
target_link_libraries(secp256k1 INTERFACE ${CMAKE_THREAD_LIBS_INIT})

add_subdirectory(crypto)
add_subdirectory(bech32)
add_subdirectory(mldsa)
