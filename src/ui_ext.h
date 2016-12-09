/**
 *
 * \file ui-ext.h
 *
 * \brief Extension to libui library
 *
 *
 * Tous droits réservés Hervé Schauer Consultants 2016 - All rights reserved Hervé Schauer Consultants 2016
 *
 * License: see LICENSE.md file
 *
 */

#if !defined( _S4_UI_EXT_H_ )
#define _S4_UI_EXT_H_

#include <ui.h>

/**
 * Display a message
 */
 void uiMsgBoxPrintf( uiWindow *parent, const char *title, const char * fmt, ... );

/**
 * Display an error message
 */
 void uiErrorBoxPrintf( uiWindow *parent, const char *title, const char * fmt, ... );

#if 0
/**
 * Directory selection box
 */
char *uiSelectDir(uiWindow *parent);
#endif 

#endif
//eof
