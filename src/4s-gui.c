// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
/**
 *
 * \file 4s-gui.c
 *
 * \brief Graphic version of the tool
 *
 *
 * Tous droits réservés Hervé Schauer Consultants 2016 - All rights reserved Hervé Schauer Consultants 2016
 *
 * License: see LICENSE.md file
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <errno.h>

#include <ui.h>

#include "shamir.h"
#include "utils.h"
#include "pki.h"
#include "shared_secret.h"
#include "gui.h"


///////////////////////////////////////////////////////////

int main(void)
{

    // context init
    s_s4context *s4c = s4_init_context();
    if( NULL == s4c ) {
        die( -1, "Application context initialisation failed.");
    }

    s_s4widgets *s4w = s4_init_widgets("4S: A Small shared secret based PKI", 400, 300, s4c );
    if( NULL == s4w ) {
        die( -1, "Windows system initialisation failed.");
    }


    // ligths on
    s4_build_gui(s4w);

	uiMain();

    // cleanup
    secure_memzero( s4c, sizeof(s_s4context) );
    secure_memzero( s4w, sizeof(s_s4widgets) );
    
    free(s4c);
    free(s4w);

	return 0;
}

