// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
/**
 *
 * \file gui_tab_unlock.c
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

#define DEEPDEBUG 1

#include "shamir.h"
#include "utils.h"
#include "shared_secret.h"
#include "gui.h"
#include "gui_strings.h"
#include "ui_ext.h"
#include "pki.h"


#define CTX_SET(var,val)     if(1) { s4w->ctx->var = (val); }
#define CTX_GET(var,val)     if(1) { (val) = s4w->ctx->var; }
#define CTX_VAL(var)         (s4w->ctx->var)
#define CTX_CPY(var,val,max) if(1) { strlcpy( (s4w->ctx->var), (val), (max)); }

#define CURRENT_TAB s4w->tab_open_pki


static void update_shared_loaded_indicator( s_s4widgets * s4w  )
{
	assert( NULL!=s4w );

	char label_loaded[255];
	
	snprintf( 
		label_loaded, sizeof(label_loaded), 
		LABEL_SHARE_LOADED, 
		s4w->ctx->nb_share_loaded, 
		s4w->ctx->quorum, (s4w->ctx->secret_unlocked?"unlocked":"locked") 
	);
	uiLabelSetText( CURRENT_TAB.lbl_loaded_shares, label_loaded );

}//eo update_shared_loaded_indicator

/**
 * Update the display of the PKI caracteristics description
 */
static void update_pki_descr (s_s4widgets * s4w) 
{
	assert( NULL!=s4w );

	char str_nb_holders[10];
	char str_quorum[10];

	snprintf( str_nb_holders, sizeof(str_nb_holders), "%u", s4w->ctx->nb_share);
	uiLabelSetText( CURRENT_TAB.lbl_nb_holders, str_nb_holders );

	snprintf( str_quorum, sizeof(str_quorum), "%u", s4w->ctx->quorum );
	uiLabelSetText( CURRENT_TAB.lbl_quorum, str_quorum );
	
	uiLabelSetText( CURRENT_TAB.lbl_pki_subject, s4w->ctx->pki_params.subject );

}//eo update_pki_gui

/**
 * Tries to load a share and update GUI to reflect result
 */
static void on_share_file_sel( uiButton * s, void * data )
{
	assert(NULL!=s);
	assert(NULL!=data);

	s_share_selector_data* sd = (s_share_selector_data*)data;

	s_s4widgets *s4w = sd->s4w;
	s_s4context *s4c = s4w->ctx;
	assert( NULL!=s4w );
	assert( NULL!=s4c );

	unsigned num = sd->num;
	
	//TODO on_share_file_sel: select secret / try to load it / check if it is the last of the quorum / if it is enable unlock button

	char *filename = uiOpenFile( s4w->mainwin );
	if ( NULL == filename ) {
		uiEntrySetText( CURRENT_TAB.keyfiles[num].txt, DEFAULT_SHARE_STATUS );
		DDEBUG_PRN("on_share_file_sel(%u): no file selected for share", num );
		return;
	}
	
	DDEBUG_PRN("on_share_file_sel(%u): file '%s' selected for share %u", num, filename );

    if( load_shamir_secret(  filename, &(s4c->shares[num]) ) ) {
        uiErrorBoxPrintf(  s4w->mainwin, "Error reading the share", "Loading share secret from %s failed", filename );

    } else {
    	char fingerprint[65];
    	shamir_share_fingerprint( &(s4c->shares[num]), fingerprint, sizeof(fingerprint) );
    	DDEBUG_PRN("on_share_file_sel(%u): fingerprint:%s", num, fingerprint);

    	char message[255];
    	snprintf(message, sizeof(message), DEFAULT_SHARE_LOADED, fingerprint );
    	uiEntrySetText( CURRENT_TAB.keyfiles[num].txt, message );

    	if( !s4c->shares_loaded[num] ) {
    		s4c->shares_loaded[num]=1;
    		s4c->nb_share_loaded++;
    		s4c->nb_share_provided++;
    	}    	
    	if( s4c->nb_share_loaded == s4c->quorum ) {
    		uiControlEnable( uiControl( CURRENT_TAB.btn_unlock ) );
    	}

    	update_shared_loaded_indicator( s4w );
   	}
    uiFreeText(filename);

}//eo on_share_file_sel

/**
 * Destroy the controls for Shamir share selection and loading
 */
void destroy_share_loaders( s_s4widgets * s4w, unsigned quorum )
{
	assert( NULL!= s4w );
	assert( quorum > 0 );

	//Creating the file selectors for each secret
	for( unsigned i=0; i<quorum; i++ ) {		

		// cleanup if existing
		if( NULL!=CURRENT_TAB.keyfiles[i].row ){
		
			DDEBUG_PRN("destroy_share_loaders: box(%p,%u)", CURRENT_TAB.box_shares, 1);
			uiBoxDelete( CURRENT_TAB.box_shares, 1 );

			DDEBUG_PRN("destroy_share_loaders: row[%u]=%p", i, CURRENT_TAB.keyfiles[i].row);
			
			uiBoxDelete( CURRENT_TAB.keyfiles[i].row, 0 );
			uiBoxDelete( CURRENT_TAB.keyfiles[i].row, 0 );
			
			uiFreeControl( uiControl(CURRENT_TAB.keyfiles[i].row) );
			CURRENT_TAB.keyfiles[i].row = NULL;

			if( NULL != CURRENT_TAB.keyfiles[i].txt ) {
				DDEBUG_PRN("destroy_share_loaders: txt[%u]=%p", i, CURRENT_TAB.keyfiles[i].txt);
				uiFreeControl( uiControl(CURRENT_TAB.keyfiles[i].txt) );		
				CURRENT_TAB.keyfiles[i].txt = NULL;
			}
			if( NULL!=CURRENT_TAB.keyfiles[i].btn ) {
				DDEBUG_PRN("destroy_share_loaders: btn[%u]=%p", i, CURRENT_TAB.keyfiles[i].btn);
				uiFreeControl( uiControl(CURRENT_TAB.keyfiles[i].btn) );			
				CURRENT_TAB.keyfiles[i].btn = NULL;
			}
		
		}
    
	}//eo foreach share
}

/**
 * Create the controls for Shamir share selection and loading
 */
void create_share_loaders( s_s4widgets * s4w, unsigned quorum )
{
	assert( NULL!= s4w );
	assert( quorum > 0 );

	char btn_label[128];

	destroy_share_loaders(s4w, quorum);

	//Creating the file selectors for each secret
	for( unsigned i=0; i<quorum; i++ ) {		

		// creating controls			
		NEW_HBOX(row_box);
		CURRENT_TAB.keyfiles[i].row = row_box;		
		CURRENT_TAB.keyfiles[i].num = i;
		CURRENT_TAB.keyfiles[i].s4w = s4w;

		CURRENT_TAB.keyfiles[i].txt = uiNewEntry();
		uiEntrySetText( CURRENT_TAB.keyfiles[i].txt , DEFAULT_SHARE_STATUS );
		uiEntrySetReadOnly( CURRENT_TAB.keyfiles[i].txt, 1 );
		
		snprintf(btn_label, sizeof(btn_label)-1, LABEL_BTN_SHARE_LOAD, i+1);
		CURRENT_TAB.keyfiles[i].btn = uiNewButton(btn_label);		 
		uiButtonOnClicked( CURRENT_TAB.keyfiles[i].btn, on_share_file_sel, &(CURRENT_TAB.keyfiles[i]) );

		// graphical setup
		BOX_APPEND( row_box, CURRENT_TAB.keyfiles[i].txt, 1);
    	BOX_APPEND( row_box, CURRENT_TAB.keyfiles[i].btn, 0);
    	BOX_APPEND( CURRENT_TAB.box_shares, row_box, 0 );
    
	}//eo foreach share
	update_shared_loaded_indicator( s4w );

}//eo create_share_loaders

/**
 * Handle lock button clicking: remove all keys from memory
 */
static void on_lock_clicked( uiButton * s, void * data )
{
	assert(NULL!=s);
	assert(NULL!=data);

	s_s4widgets * s4w = (s_s4widgets*)data;
	s_s4context *s4c = s4w->ctx;

	//erase all secrets
	if( s4c->secret_unlocked ) {
		s4c->secret_unlocked = 0;
		s4c->passphrase_len=0;
		secure_memzero( s4c->passphrase,  MAX_B64_ENC_PASS_SIZE );
		for( unsigned i=0; i<s4c->quorum; i++ ) {
			secure_memzero( &(s4c->shares[i]), sizeof(s_share_t) );			
		}
		s4c->nb_share_loaded = 0;
		s4c->nb_share_provided = 0;
		secure_memzero( s4c->shares_loaded, sizeof(int)*MAX_SHAMIR_SHARE_NUMBER );

		create_share_loaders(s4w, s4c->quorum );		

	}//eo if unlocked
	if( NULL != s4w->on_pki_locked ) {
		s4w->on_pki_locked(s4w);
	}

	uiControlDisable( uiControl( CURRENT_TAB.btn_unlock ) );
	uiControlDisable( uiControl( CURRENT_TAB.btn_lock ) );

}//eo on_lock_clicked

/**
 * Handle the unlock button clicking: try to recover the passphrase from the share secerts
 */
static void on_unlock_clicked( uiButton * s, void * data )
{
	assert(NULL!=s);
	assert(NULL!=data);

    size_t  secret_max_size = MAX_HEX_ENC_PASS_SIZE+1;
    uint8_t secret[secret_max_size];

	s_s4widgets *s4w = (s_s4widgets*)data;
	s_s4context *s4c = s4w->ctx;

	assert( NULL != s4c );

	if( s4c->nb_share_loaded < s4c->quorum ) {
		uiMsgBox( s4w->mainwin, "Shamir recovery impossible","Not enough share where loaded to unlock the secret");
		return;
	}

	//Recontruct secret
    int r1 = do_shamir_recovery( s4c->nb_share_provided, s4c->shares, secret, secret_max_size );
	if( r1 != EXIT_SUCCESS ) {
        uiErrorBoxPrintf( s4w->mainwin, "Shamir recovery failed","Failed to recoved the splitted secret");
		return;
	}

	//base64_ encode the pass phrase 
    ssize_t r2 = base64_encode( s4c->passphrase, MAX_B64_ENC_PASS_SIZE, secret, PASS_SIZE);
	if( r2 <0 ) {
        die( -1, "base64 encoding of the passphrase failed");
    }    
    s4c->passphrase_len = r2;
    s4c->secret_unlocked = 1;

	if( NULL!=s4w->on_pki_unlocked ) {
		s4w->on_pki_unlocked(s4w);
	}
	uiMsgBoxPrintf(s4w->mainwin, "Certification Authority unlocked", "You can now use PKI operations or regenerate a secret share.");


    update_shared_loaded_indicator( s4w );

    uiControlDisable( uiControl( CURRENT_TAB.btn_unlock ) );
	uiControlEnable( uiControl( CURRENT_TAB.btn_lock ) );
    	
}//eo on_unlock_clicked


static void on_pki_sel_dir_clicked( uiButton * s, void * data )
{
	assert(NULL!=s);
	assert(NULL!=data);

    s_s4widgets * s4w = (s_s4widgets*)data;


	char *dirname = uiSelectDir(s4w->mainwin);
	if ( NULL == dirname ) {
		uiEntrySetText( CURRENT_TAB.txt_pki_dir, DEFAULT_PKI_DIR );
		return;
	}
    CTX_CPY( pki_params.root_dir, dirname, MAX_FILE_PATH);

	uiEntrySetText(CURRENT_TAB.txt_pki_dir, dirname);    

    if( try_to_open_pki_info(s4w->ctx, dirname) < 0 ) {    	
    	DDEBUG_PRN("The directory you selected does not contain an initialized PKI");
    	uiMsgBox( s4w->mainwin, "Incorrect directory:","The directory you selected does not contain an initialized PKI" );  
    } else {
    	update_pki_descr(s4w);
    	create_share_loaders( s4w, s4w->ctx->quorum );    	
    	update_shared_loaded_indicator( s4w );
    	
		if( NULL!=s4w->tab_pki_operations.on_pki_loaded ) {
			s4w->tab_pki_operations.on_pki_loaded(s4w);
		}
    }
    uiFreeText(dirname);

}//eo on_pki_sel_dir_clicked

#undef CTX_SET
#undef CTX_GET
#undef CTX_VAL
#undef CTX_CPY


////////////////////////////////////////////////////////////////
//

uiControl *create_unlock_page( s_s4widgets * s4w )
{
    /*
                                       |
                                       |Keys:
    [ PKI directory ] [pkidir btn]     | 
    -----------------------------------| [ file key 1        ] [k1 btn]
    Subject: <subject text>            | [ file key 2        ] [k2 btn]
    Nb Key holders: <lbl_num_holders>  | [ file key 3        ] [k3 btn]
    Quorum: <lbl_quorum>               | [ file key 4        ] [k4 btn]
    -----------------------------------| [ file key 5        ] [k5 btn]
     [unlock btn]     [lock btn]       |
                                       |

    */

    assert( NULL!=s4w );

    // event handlers
    CURRENT_TAB.on_sel_pki_root_dir_click = on_pki_sel_dir_clicked;
	CURRENT_TAB.on_lock_click   = on_lock_clicked;
	CURRENT_TAB.on_unlock_click = on_unlock_clicked;

    //////////////
    NEW_ROWBOX(btn_box);
    NEW_ROWBOX(dir_box);
	NEW_ROWBOX(subj_box);
	NEW_ROWBOX(count_box);
	NEW_ROWBOX(quorum_box);

	NEW_GROUP(group_infos, vbox_pki_infos, LABEL_GROUP_PKI_PARAMETERS);

	// PKI root directory selection    
    CURRENT_TAB.txt_pki_dir     = uiNewEntry();
    uiEntrySetText(CURRENT_TAB.txt_pki_dir , DEFAULT_PKI_DIR);
	uiEntrySetReadOnly(CURRENT_TAB.txt_pki_dir, 1);
	
	NEW_BUTTON( CURRENT_TAB.btn_sel_pki_dir, LABEL_SELECT_ROOT_DIR, CURRENT_TAB.on_sel_pki_root_dir_click );

	BOX_APPEND( dir_box, CURRENT_TAB.txt_pki_dir, 1);
    BOX_APPEND( dir_box, CURRENT_TAB.btn_sel_pki_dir, 0);    

    CURRENT_TAB.lbl_pki_subject = uiNewLabel(DEFAULT_ROOT_SUBJECT);
    CURRENT_TAB.lbl_nb_holders  = uiNewLabel(DEFAULT_NUM);
    CURRENT_TAB.lbl_quorum      = uiNewLabel(DEFAULT_NUM);

	NEW_BUTTON( CURRENT_TAB.btn_unlock, LABEL_BTN_UNLOCK, CURRENT_TAB.on_unlock_click );

	NEW_BUTTON( CURRENT_TAB.btn_lock, LABEL_BTN_LOCK, CURRENT_TAB.on_lock_click );

	// building rows
 	BOX_APPEND( subj_box,   uiNewLabel(LABEL_ROOT_SUBJECT), 1);
    BOX_APPEND( subj_box,    CURRENT_TAB.lbl_pki_subject,   0);

	BOX_APPEND( count_box,  uiNewLabel(LABEL_SHARE_COUNT),  1);
    BOX_APPEND( count_box,  CURRENT_TAB.lbl_nb_holders,     0);

	BOX_APPEND( quorum_box, uiNewLabel(LABEL_QUORUM_SIZE),  1);
    BOX_APPEND( quorum_box, CURRENT_TAB.lbl_quorum,         0);

	BOX_APPEND( btn_box,    CURRENT_TAB.btn_unlock,        1);
	BOX_APPEND( btn_box,    CURRENT_TAB.btn_lock,          1);

	// stacking rows
 	BOX_APPEND( vbox_pki_infos, dir_box,                    0);
 	BOX_APPEND( vbox_pki_infos, uiNewHorizontalSeparator(), 0);
 	BOX_APPEND( vbox_pki_infos, subj_box,                   0);    
    BOX_APPEND( vbox_pki_infos, count_box,                  0);
    BOX_APPEND( vbox_pki_infos, quorum_box,                 0);
    BOX_APPEND( vbox_pki_infos, uiNewHorizontalSeparator(), 0);
	BOX_APPEND( vbox_pki_infos, btn_box,                    0);

    ///////// Shares group
    NEW_GROUP( group_shares, vbox_shares, LABEL_GROUP_SHARES );
    CURRENT_TAB.box_shares = vbox_shares;

    CURRENT_TAB.lbl_loaded_shares = uiNewLabel(LABEL_SHARE_LOADED_INIT);
	BOX_APPEND(vbox_shares, CURRENT_TAB.lbl_loaded_shares, 0);
    
	/////////////////////////////////////////// Page assembly
	NEW_HBOX(hbox);
	NEW_VBOX(vbox_left);
	NEW_VBOX(vbox_right);
	
	BOX_APPEND( hbox, vbox_left,  1);
	BOX_APPEND( hbox, vbox_right, 1);

	BOX_APPEND( vbox_left,  group_infos,  1);
	BOX_APPEND( vbox_right, group_shares, 1);

	

	// initial state
	uiControlDisable( uiControl( CURRENT_TAB.btn_unlock ) );
	uiControlDisable( uiControl( CURRENT_TAB.btn_lock   ) );
	
	return uiControl(hbox);
}//eo create_unlock_page



// eof

