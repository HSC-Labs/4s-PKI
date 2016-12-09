// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
/**
 *
 * \file gui_tab_operations.c
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
#include "ui_ext.h"
#include "pki.h"

#define CURRENT_TAB s4w->tab_pki_operations
#define CTX_CPY(var,val,max) if(1) { strlcpy( (s4w->ctx->var), (val), (max)); }

static void on_pki_loaded ( s_s4widgets* s4w )
{
    assert( NULL!=s4w ); 


    char str_nb_emitted[10];
    char str_nb_revoqued[10];

    snprintf( str_nb_emitted, sizeof(str_nb_emitted), "%u", s4w->ctx->nb_emitted);
    uiLabelSetText( CURRENT_TAB.lbl_subca_count, str_nb_emitted );

    snprintf( str_nb_revoqued, sizeof(str_nb_revoqued), "%u", s4w->ctx->nb_revoqued );
    uiLabelSetText( CURRENT_TAB.lbl_revoq_count, str_nb_revoqued );
    
    uiLabelSetText( CURRENT_TAB.lbl_pki_subject, s4w->ctx->pki_params.subject );

    //lbl_last_CRL_date;
}//eo on_pki_loaded

static void on_cert_2_revoke_file_sel_clicked( uiButton * s, void * data )
{
	assert(NULL!=s);
	assert(NULL!=data);

    s_s4widgets * s4w = (s_s4widgets*)data;

	char *filename = uiOpenFile(s4w->mainwin);
	if ( NULL == filename ) {
		uiEntrySetText( CURRENT_TAB.txt_revoq_cert_file, DEFAULT_INPUT_FILE );
		return;
	}
    CTX_CPY( cert_path, filename, MAX_FILE_PATH);

	uiEntrySetText(CURRENT_TAB.txt_revoq_cert_file, filename);
    uiFreeText(filename);
}//eo onOpenPKISelDirClicked


static void on_csr_file_sel_clicked( uiButton * s, void * data )
{
	assert(NULL!=s);
	assert(NULL!=data);

    s_s4widgets * s4w = (s_s4widgets*)data;

	char *filename = uiOpenFile(s4w->mainwin);
	if ( NULL == filename ) {
		uiEntrySetText( CURRENT_TAB.txt_csr_file, DEFAULT_INPUT_FILE );
		return;
	}
    CTX_CPY( csr_path, filename, MAX_FILE_PATH);

	uiEntrySetText( CURRENT_TAB.txt_csr_file, filename);

    uiFreeText(filename);
}//eo onOpenPKISelDirClicked

static void on_sign_clicked( uiButton * s, void * data )
{
    assert(NULL!=s);
    assert(NULL!=data);

    s_s4widgets * s4w = (s_s4widgets*)data;
    s_s4context * s4c = s4w->ctx;
    assert( NULL!=s4c );

    char *filename = uiSaveFile(s4w->mainwin);
    if ( NULL == filename ) {        
        return;
    }
    CTX_CPY( cert_path, filename, MAX_FILE_PATH);

    DDEBUG_PRN(  "on_sign_clicked: signing('%s') => '%s' ", s4c->csr_path, s4c->cert_path );

    // Do the sub CA signing
    if( sign_subca( s4c->pki_params.root_dir, s4c->csr_path, s4c->cert_path, s4c->passphrase,  &(s4w->pki_events_handlers) ) != 0 ) {
        uiErrorBoxPrintf(s4w->mainwin, "Signature failed", "Failed to sign CSR: %s", s4c->csr_path ); 
        return;        
    }

}//eo on_sign_clicked

static void on_revoke_clicked( uiButton * s, void * data )
{
	assert(NULL!=s);
	assert(NULL!=data);

    s_s4widgets * s4w = (s_s4widgets*)data;
    s_s4context * s4c = s4w->ctx;
    assert( NULL!=s4c );

    DDEBUG_PRN( "on_revoke_clicked: revocating('%s')", s4c->cert_path );

    if( revoke_subca( s4c->pki_params.root_dir, s4c->cert_path, s4c->passphrase, &(s4w->pki_events_handlers)) != 0 ) {
        uiErrorBoxPrintf(s4w->mainwin, "Revocation failed", "Failed to revoke cert:%s", s4c->cert_path );          
        return;
    }

}//eo on_revoke_clicked



static void on_gen_crl_clicked( uiButton *s, void * data )
{
    assert(NULL!=s);
    assert(NULL!=data);

    s_s4widgets * s4w = (s_s4widgets*)data;
    s_s4context * s4c = s4w->ctx;
    assert( NULL!=s4c );

    char *filename = uiSaveFile(s4w->mainwin);
    if ( NULL == filename ) {        
        return;
    }
    CTX_CPY( crl_path, filename, MAX_FILE_PATH);

    DDEBUG_PRN(  "on_gen_crl_clicked: generating_crl('%s')", s4c->crl_path );

    if( generate_crl( s4c->pki_params.root_dir, s4c->crl_path, s4c->passphrase, &(s4w->pki_events_handlers)) != 0 ) {
        uiErrorBoxPrintf(s4w->mainwin, "Revocation failed", "Failed to revoke cert:%s", s4c->cert_path );          
        return;
    }

}//eo on_gen_crl_clicked

////////////////////////////////////////////////////////////////
//
uiControl *create_operations_page( s_s4widgets * s4w )
{

    /*
                                         |
    Subject: <subject text>              |
    -------------------------------------|  Revoke sub-CA
                                         | [ certificate file ] [cert_ btn]
    Nb sub-CA emitted: <lbl subca count> |                  [ publish CRL ]
    Nb sub-CA revocated: <lbl>           |--------------------------------------
    Last CRL:                            | Sign sub-CA     
    -------------------------------------| [CSR file           ]  [CSR btn]
                                         |                         [ sign ]
                                         |
    */        

	assert( NULL!=s4w );   

    CURRENT_TAB.on_sign_click=on_sign_clicked;        
    CURRENT_TAB.on_revoke_click=on_revoke_clicked;        
    CURRENT_TAB.on_csr_sel_click=on_csr_file_sel_clicked;        
    CURRENT_TAB.on_cert_sel_click=on_cert_2_revoke_file_sel_clicked;    
    CURRENT_TAB.on_gen_crl_click=on_gen_crl_clicked;


    CURRENT_TAB.on_pki_loaded = on_pki_loaded;

	///////////////////////////// Controls creation
    CURRENT_TAB.lbl_pki_status    = uiNewLabel(LABEL_PKI_STATUS_LOCKED);
    CURRENT_TAB.lbl_pki_subject   = uiNewLabel(DEFAULT_ROOT_SUBJECT);
    CURRENT_TAB.lbl_subca_count   = uiNewLabel(DEFAULT_NUM);
    CURRENT_TAB.lbl_revoq_count   = uiNewLabel(DEFAULT_NUM);
    CURRENT_TAB.lbl_last_CRL_date = uiNewLabel(DEFAULT_TIMESTAMP);

    CURRENT_TAB.txt_revoq_cert_file = uiNewEntry();
    uiEntrySetText(CURRENT_TAB.txt_revoq_cert_file , DEFAULT_INPUT_FILE);
	uiEntrySetReadOnly(CURRENT_TAB.txt_revoq_cert_file, 1);
    
    NEW_BUTTON( CURRENT_TAB.btn_revoq_cert_file, LABEL_BTN_SEL_CERT, CURRENT_TAB.on_cert_sel_click );
  
    NEW_BUTTON( CURRENT_TAB.btn_revocate, LABEL_BTN_REVOKE, CURRENT_TAB.on_revoke_click );
        
    CURRENT_TAB.txt_csr_file = uiNewEntry();
    uiEntrySetText( CURRENT_TAB.txt_csr_file , DEFAULT_INPUT_FILE);
	uiEntrySetReadOnly( CURRENT_TAB.txt_csr_file, 1);

    NEW_BUTTON( CURRENT_TAB.btn_csr_file, LABEL_BTN_SEL_CSR, CURRENT_TAB.on_csr_sel_click );

    NEW_BUTTON( CURRENT_TAB.btn_sign, LABEL_BTN_SIGN, CURRENT_TAB.on_sign_click );

    NEW_BUTTON( CURRENT_TAB.btn_gen_crl, LABEL_BTN_GEN_CRL, CURRENT_TAB.on_gen_crl_click );

	///////////////////////////// Layout

    //// LEFT

    // Building rows
    NEW_ROWBOX(status_box);
  	NEW_ROWBOX(subject_box);
	NEW_ROWBOX(subca_count_box);
	NEW_ROWBOX(revocations_count_box);
	NEW_ROWBOX(last_crl_box);
    
    BOX_APPEND( status_box, uiNewLabel(LABEL_PKI_STATUS), 1);
    BOX_APPEND( status_box, CURRENT_TAB.lbl_pki_status,    0);
    

    BOX_APPEND( subject_box, uiNewLabel(LABEL_ROOT_SUBJECT), 1);
	BOX_APPEND( subject_box, CURRENT_TAB.lbl_pki_subject,    0);
	
	BOX_APPEND( subca_count_box, uiNewLabel(LABEL_SUBCA_COUNT), 1);
	BOX_APPEND( subca_count_box, CURRENT_TAB.lbl_subca_count,   0);

	BOX_APPEND( revocations_count_box, uiNewLabel(LABEL_REVOCATIONS_COUNT), 1);
	BOX_APPEND( revocations_count_box, CURRENT_TAB.lbl_revoq_count,         0);

	BOX_APPEND( last_crl_box, uiNewLabel(LABEL_LAST_CRL),    1);
	BOX_APPEND( last_crl_box, CURRENT_TAB.lbl_last_CRL_date, 0);

     
    // Rows stacking
    NEW_GROUP(group_info, vbox_pki_infos,  LABEL_GROUP_PKI_INFO);
    
    BOX_APPEND( vbox_pki_infos, status_box,                 0);
    BOX_APPEND( vbox_pki_infos, uiNewHorizontalSeparator(), 0);
    BOX_APPEND( vbox_pki_infos, subject_box,                0);
    BOX_APPEND( vbox_pki_infos, uiNewHorizontalSeparator(), 0);
    BOX_APPEND( vbox_pki_infos, subca_count_box,            0);
    BOX_APPEND( vbox_pki_infos, revocations_count_box,      0);
    BOX_APPEND( vbox_pki_infos, last_crl_box,               0);
    BOX_APPEND( vbox_pki_infos, uiNewHorizontalSeparator(), 0);

    //// RIGHT

	//////// Signature group

    // Building rows
	NEW_ROWBOX( csrsel_box );
    BOX_APPEND( csrsel_box, CURRENT_TAB.txt_csr_file, 1);
    BOX_APPEND( csrsel_box, CURRENT_TAB.btn_csr_file, 0);

    NEW_ROWBOX(sign_box);
	BOX_APPEND( sign_box, uiNewLabel("     "), 1);
    BOX_APPEND( sign_box, CURRENT_TAB.btn_sign, 0);

    // Row stacking
    NEW_GROUP( group_sign, vbox_sign, LABEL_GROUP_SIGNATURE);

    BOX_APPEND( vbox_sign, csrsel_box, 0);
    BOX_APPEND( vbox_sign, sign_box,  0);

    BOX_APPEND( vbox_sign, uiNewHorizontalSeparator(), 0);

    //////// Revocation group

    // Building rows
    NEW_ROWBOX( certsel_box );
    BOX_APPEND( certsel_box, CURRENT_TAB.txt_revoq_cert_file, 1);
    BOX_APPEND( certsel_box, CURRENT_TAB.btn_revoq_cert_file, 0);

    NEW_ROWBOX( revoke_box );
    BOX_APPEND( revoke_box, uiNewLabel("     "), 1);
    BOX_APPEND( revoke_box, CURRENT_TAB.btn_revocate, 0);

    // Row stacking
    NEW_GROUP( group_rev,  vbox_revocation, LABEL_GROUP_REVOCATION );

    BOX_APPEND( vbox_revocation, certsel_box, 0);
    BOX_APPEND( vbox_revocation, revoke_box,  0);
    BOX_APPEND( vbox_revocation, uiNewHorizontalSeparator(), 0);

    //////// CRL Emission
    NEW_ROWBOX( crl_box );
    BOX_APPEND( crl_box, uiNewLabel("     "), 1);
    BOX_APPEND( crl_box, CURRENT_TAB.btn_gen_crl, 0);

    NEW_GROUP( group_crl, vbox_crl, LABEL_GROUP_CRL );

    BOX_APPEND( vbox_crl, crl_box, 0 );
    BOX_APPEND( vbox_crl, uiNewHorizontalSeparator(), 0);

    /////////////////////////////////////////// Page assembly

    NEW_HBOX(hbox);
	NEW_VBOX(vbox_left);

	NEW_VBOX(vbox_right);
    BOX_APPEND( hbox, vbox_left,  1);
	BOX_APPEND( hbox, vbox_right, 1);

	BOX_APPEND( vbox_left,  group_info, 1);

    BOX_APPEND( vbox_right, group_sign, 1);
	BOX_APPEND( vbox_right, group_rev,  1);	
    BOX_APPEND( vbox_right, group_crl, 1);

	return uiControl(hbox);
}//eo create_operations_page

// eof

