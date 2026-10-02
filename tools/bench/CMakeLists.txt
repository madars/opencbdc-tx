project(bench)

include_directories(../../src ../../3rdparty ../../3rdparty/secp256k1/include)

add_executable(twophase-gen twophase_gen.cpp)
target_link_libraries(twophase-gen sentinel
                                   sentinel_interface
                                   locking_shard
                                   coordinator
                                   raft
                                   transaction
                                   rpc
                                   network
                                   common
                                   serialization
                                   crypto
                                   ${NURAFT_LIBRARY}
                                   ${LEVELDB_LIBRARY}
                                   secp256k1
                                   ${CMAKE_THREAD_LIBS_INIT})

add_executable(atomizer-cli-watchtower atomizer-cli-watchtower.cpp)
target_link_libraries(atomizer-cli-watchtower watchtower
                                              archiver
                                              atomizer
                                              sentinel
                                              sentinel_interface
                                              raft
                                              rpc
                                              transaction
                                              network
                                              common
                                              serialization
                                              crypto
                                              secp256k1
                                              ${NURAFT_LIBRARY}
                                              ${LEVELDB_LIBRARY}
                                              ${CMAKE_THREAD_LIBS_INIT})

add_executable(dilithium-bench dilithium_bench.c)
target_compile_definitions(dilithium-bench PRIVATE DILITHIUM_MODE=${MLDSA_MODE})
target_link_libraries(dilithium-bench mldsa)

add_executable(sentinel-bench sentinel_bench.cpp)
target_link_libraries(sentinel-bench transaction
                                       serialization
                                       common
                                       crypto
                                       secp256k1
                                       mldsa
                                       ${CMAKE_THREAD_LIBS_INIT})

add_subdirectory(parsec)
