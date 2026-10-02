project(client)

add_library(client atomizer_client.cpp
                   client.cpp
                   twophase_client.cpp)


add_executable(client-cli client-cli.cpp)
target_link_libraries(client-cli client
                                 atomizer
                                 watchtower
                                 archiver
                                 sentinel
                                 sentinel_interface
                                 transaction
                                 locking_shard
                                 coordinator
                                 raft
                                 rpc
                                 network
                                 common
                                 serialization
                                 crypto
                                 secp256k1
                                 ${LEVELDB_LIBRARY}
                                 ${NURAFT_LIBRARY}
                                 ${CMAKE_THREAD_LIBS_INIT})
