/**
 *
 * \file gui.c
 *
 * \brief User interface basic functions
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
#include <stdarg.h>

#include <ui.h>

#include "shamir.h"
#include "utils.h"
#include "shared_secret.h"
#include "gui.h"
#include "gui_strings.h"


static int onClosing(uiWindow *w, void *data)
{
	uiQuit();
	return 1;
}//eo onClosing

static int onShouldQuit(void *data)
{
	assert( NULL!=data );

	s_s4widgets *s4w = (s_s4widgets*)data;
	uiControlDestroy(uiControl(s4w->mainwin));
	return 1;
}//eo onShouldQuit

static void gui_warning_handler( void * data, const char * fmt, ... ) 
{
	assert( NULL!=data );

	s_s4widgets * w = (s_s4widgets*)data;
	va_list args;
	va_start (args, fmt);

	char message[MAX_MESSAGE_SIZE+1];

	vsnprintf( message, MAX_MESSAGE_SIZE, fmt, args);
	uiMsgBox(w->mainwin,"Warning",message);

	va_end(args);
}

static void gui_message_handler(void* data, const char * title, const char *message)
{ 
	assert( NULL!=data );
	//TODO
}

static int gui_file_prompt_handler(void* data, const char * prompt, char* filepath, size_t  filepath_max)
{
	assert( NULL!=data );
	//TODO
	return 0;
}

///////////////////////////////// Exported functions


s_s4widgets* s4_init_widgets(const char * title, int w, int l, s_s4context * ctx ) 
{
	assert( NULL!=ctx );

    s_s4widgets * s4w = (s_s4widgets*) malloc( sizeof( s_s4widgets ) );
    if( NULL == s4w ) {
        warn("Failed to allocate memory for widgets structure");
        return NULL;
    }

    secure_memzero( (void*)s4w, sizeof(s_s4widgets));

	s4w->ctx=ctx;

    uiInitOptions options;
   	memset(&options, 0, sizeof (uiInitOptions));
	const char *err = uiInit(&options);
	if ( NULL != err ) {
		warn("error initializing libui: %s", err);
		uiFreeInitError(err);
		return NULL;
	}

    s4w->mainwin = uiNewWindow( title, w, l, 1);
    uiWindowOnClosing( s4w->mainwin, onClosing, s4w );
	uiOnShouldQuit( onShouldQuit, s4w);

    // data for handlers
	s4w->pki_events_handlers.data = (void*)s4w;
	s4w->pki_events_handlers.on_warning     = gui_warning_handler;
	s4w->pki_events_handlers.do_message     = gui_message_handler;
	s4w->pki_events_handlers.do_file_prompt = gui_file_prompt_handler;

    return s4w;
}//eo s4_init_widgets

#define CURRENT_TAB 
#define CTX_CPY(var,val,max) if(1) { strlcpy( (s4w->ctx->var), (val), (max)); }

void on_pki_locked ( s_s4widgets* s4w )
{
    assert( NULL!=s4w );

    // Operations TAB
    uiLabelSetText( s4w->tab_pki_operations.lbl_pki_status, LABEL_PKI_STATUS_LOCKED );

    uiControlDisable( uiControl(s4w->tab_pki_operations.txt_revoq_cert_file));
    uiControlDisable( uiControl(s4w->tab_pki_operations.btn_revoq_cert_file));
    uiControlDisable( uiControl(s4w->tab_pki_operations.btn_revocate));

    uiControlDisable( uiControl(s4w->tab_pki_operations.txt_csr_file));
    uiControlDisable( uiControl(s4w->tab_pki_operations.btn_csr_file));
    uiControlDisable( uiControl(s4w->tab_pki_operations.btn_sign));

    uiControlDisable( uiControl(s4w->tab_pki_operations.btn_gen_crl));

    // Rekey TAB
     uiLabelSetText( s4w->tab_rekey_share.lbl_pki_status, LABEL_PKI_STATUS_LOCKED );
    uiControlDisable( uiControl( s4w->tab_rekey_share.spin_quorum     ));
    uiControlDisable( uiControl( s4w->tab_rekey_share.spin_share_count));
    uiControlDisable( uiControl( s4w->tab_rekey_share.btn_rekey       ));
        
    //uiControlDisable( uiControl( s4w->tab_rekey_share.lbl_export_progress    ));
    //uiControlDisable( uiControl( s4w->tab_rekey_share.bar_share_export_status));
    //uiControlDisable( uiControl( s4w->tab_rekey_share.btn_export_share       ));
}//eo on_pki_locked

void on_pki_unlocked ( s_s4widgets* s4w )
{
    assert( NULL!=s4w );    

    // Operations TAB
    uiLabelSetText( s4w->tab_pki_operations.lbl_pki_status, LABEL_PKI_STATUS_UNLOCKED );

    uiControlEnable( uiControl(s4w->tab_pki_operations.txt_revoq_cert_file ));
    uiControlEnable( uiControl(s4w->tab_pki_operations.btn_revoq_cert_file ));
    uiControlEnable( uiControl(s4w->tab_pki_operations.btn_revocate ));

    uiControlEnable( uiControl(s4w->tab_pki_operations.txt_csr_file));
    uiControlEnable( uiControl(s4w->tab_pki_operations.btn_csr_file ));
    uiControlEnable( uiControl(s4w->tab_pki_operations.btn_sign ));

    uiControlEnable( uiControl( s4w->tab_pki_operations.btn_gen_crl ));

    // Rekey TAB
    uiLabelSetText( s4w->tab_rekey_share.lbl_pki_status, LABEL_PKI_STATUS_UNLOCKED );
    uiControlEnable( uiControl( s4w->tab_rekey_share.spin_quorum ));
    uiControlEnable( uiControl( s4w->tab_rekey_share.spin_share_count ));
    uiControlEnable( uiControl( s4w->tab_rekey_share.btn_rekey ));
        
    //uiControlEnable( uiControl( s4w->tab_rekey_share.lbl_export_progress ));
    //uiControlEnable( uiControl( s4w->tab_rekey_share.bar_share_export_status ));
    //uiControlEnable( uiControl( s4w->tab_rekey_share.btn_export_share ));

}//eo on_pki_unlocked


void s4_build_gui( s_s4widgets* s4w )
{
	assert( NULL!=s4w );

	uiTab *tab = uiNewTab();

    s4w->on_pki_unlocked = on_pki_unlocked;
    s4w->on_pki_locked = on_pki_locked;

	uiWindowSetChild( s4w->mainwin, uiControl(tab));
	uiWindowSetMargined( s4w->mainwin, 1);

	uiTabAppend( tab, "Lock/Unlock PKI",     create_unlock_page(s4w) );
	uiTabSetMargined( tab, 0, 1);

	uiTabAppend( tab, "PKI Operations", create_operations_page(s4w) );
	uiTabSetMargined( tab, 1, 1);

	uiTabAppend( tab, "Regenerate Shamir share", create_rekey_page(s4w) );
	uiTabSetMargined( tab, 2, 1);

	uiTabAppend( tab, "Create a new PKI",   create_pki_page(s4w) );
	uiTabSetMargined( tab, 3, 1);

	uiControlShow( uiControl( s4w->mainwin ) );

	s4w->tab_create_pki.on_pki_uninitialized( s4w );	
    s4w->on_pki_locked(s4w);
}//eo s4_build_gui

//eof 

