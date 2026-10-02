project(common)

add_library(common buffer.cpp
                   hash.cpp
                   keys.cpp
                   mldsa.cpp
                   config.cpp
                   logging.cpp
                   random_source.cpp
                   thread_pool.cpp)

target_link_libraries(common PUBLIC mldsa)
