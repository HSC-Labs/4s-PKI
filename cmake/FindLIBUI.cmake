find_path(LIBUI_INCLUDE_DIR ui.h "${LIBUI_DIR}/include")
find_library(LIBUI ui "${LIBUI_DIR}/lib")
set(LIBUI_LIBRARIES  ${LIBUI})
set(LIBUI_INCLUDE_DIRS ${LIBUI_INCLUDE_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(LIBUI DEFAULT_MSG LIBUI_LIBRARIES LIBUI_INCLUDE_DIR)

mark_as_advanced(LIBUI_INCLUDE_DIR LIBUI)
