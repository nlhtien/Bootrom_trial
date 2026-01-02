option(INSTALL_TF_PSA_CRYPTO_HEADERS "Install TF PSA Crypto headers." ON)

if(INSTALL_TF_PSA_CRYPTO_HEADERS)
    install(DIRECTORY "."
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING PATTERN "*.h"
    )
endif(INSTALL_TF_PSA_CRYPTO_HEADERS)

# Make includes available in an out-of-source build. ssl-opt.sh requires it.
if (ENABLE_TESTING AND NOT ${CMAKE_CURRENT_BINARY_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    tf_psa_crypto_link_to_source(psa)
endif()
