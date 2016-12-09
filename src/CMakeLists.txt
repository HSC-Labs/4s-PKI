

# Commande line binary
add_executable(4s-cli shamir.c utils.c shared_secret.c pki.c 4s-cli.c cliopt.c bsd-strlcpy.c base64.c sha3.c )
target_link_libraries(4s-cli ${LIBS})
target_include_directories(4s-cli PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>)


# GUI binary
add_executable(4s-gui shamir.c utils.c shared_secret.c pki.c gui.c 4s-gui.c bsd-strlcpy.c base64.c sha3.c ui_ext.c gui_tab_create.c  gui_tab_operations.c gui_tab_unlock.c gui_tab_rekey.c )
target_link_libraries(4s-gui ${LIBS})
target_include_directories(4s-gui PRIVATE $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>)


