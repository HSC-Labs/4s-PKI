// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
/**
 *
 * \file gui_tab_rekey.c
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

#define CURRENT_TAB s4w->tab_rekey_share


/**
 * Check whether Shamir Share parameters are consistant
 */
static void check_shamir_settings( s_s4widgets * s4w ) 
{
	assert( NULL!=s4w );

    int q = CTX_VAL(quorum);
    int n = CTX_VAL(nb_share);
    if( q >= n ) {
        uiMsgBox( s4w->mainwin,
            "Attention",
            "quorum has to be smaller than the number of secret holders"
        );
        q = n -1;
        CTX_SET(quorum, q);
        CTX_SET(nb_share, n);

        uiSpinboxSetValue( CURRENT_TAB.spin_quorum, q ) ;
        uiSpinboxSetValue( CURRENT_TAB.spin_share_count, n);
    }
}//eo check_shamir_settings



/**
 * Event handler for Quorum count change
 */ 
static void onSpinboxQuorumChanged(uiSpinbox *s, void *data)
{
	assert(NULL!=s);
	assert(NULL!=data);

    s_s4widgets * s4w = (s_s4widgets*)data;
    CTX_SET( quorum, uiSpinboxValue(s) );
    check_shamir_settings(s4w);  

}//eo onSpinboxquorumChanged

/**
 * Event handler for share count change
 */
static void onSpinboxShareCountChanged(uiSpinbox *s, void *data)
{
	assert(NULL!=s);
	assert(NULL!=data);
	    
    s_s4widgets * s4w = (s_s4widgets*)data;
    CTX_SET( nb_share, uiSpinboxValue(s) );
    check_shamir_settings(s4w);
}//eo onSpinboxShareCountChanged


static void onExportShareClicked( uiButton * s, void * data )
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
    CTX_CPY( crl_path, filename, MAX_FILE_PATH)
    
    
    if( s4c->nb_share_exported == s4c->nb_share ) {
        s4c->nb_share_exported = 0;
    }
    //Export next share
    int res = save_shamir_secret( filename, &(s4c->shares[s4c->nb_share_exported]));
    if( res ) {
        uiErrorBoxPrintf( 
            s4w->mainwin, 
            "Export failed", 
            "Exporting the %uth Shamir share to %s failed", 
            s4c->nb_share_exported+1, filename 
        );
    } else {
        uiMsgBoxPrintf( s4w->mainwin, "Export succedeed", "%uth Shamir share saved to '%s'", s4c->nb_share_exported, filename);
        s4c->nb_share_exported++;
        
        int pct = INTPCT(s4c->nb_share, s4c->nb_share_exported); 
        uiProgressBarSetValue(CURRENT_TAB.bar_share_export_status, pct);
        char label[128];
        snprintf( label, sizeof(label), LABEL_EXPORT_PROGRESS_UPDT, s4c->nb_share_exported, s4c->nb_share);
        uiLabelSetText( CURRENT_TAB.lbl_export_progress, label );
        
        if( s4c->nb_share_exported < s4c->nb_share ) {
            uiButtonSetText(s, LABEL_BTN_EXPORT_NEXT);
        } else {
            uiButtonSetText(s, LABEL_BTN_EXPORT_RESET);
        }
    }//eo if export succedeed 
    uiFreeText(filename);
}//eo onExportShareClicked

static void onRekeyClicked( uiButton * s, void * data )
{
    assert(NULL!=s);
	assert(NULL!=data);
	    
    s_s4widgets * s4w = (s_s4widgets*)data;
    s_s4context * s4c = s4w->ctx;
    assert( NULL != s4c );
    
    // TODO check that we are unloacked
    
    if( s4_split( s4c, &(s4w->pki_events_handlers) ) ) {
        uiErrorBoxPrintf(s4w->mainwin, "Secret splitting failed","Unable to perform Shamir secret splitting");
        return;        
    }    

}//eo onRekeyClicked

#undef CTX_SET
#undef CTX_GET
#undef CTX_VAL
#undef CTX_CPY

////////////////////////////////////////////////////////////////
//

uiControl *create_rekey_page( s_s4widgets * s4w )
{

    assert( NULL!=s4w );

    // associating ui event handlers
    CURRENT_TAB.on_rekey_click = onRekeyClicked;
    CURRENT_TAB.on_export_share_click = onExportShareClicked;
    CURRENT_TAB.on_quorum_spinbox_change = onSpinboxQuorumChanged; 
    CURRENT_TAB.on_share_num_spinbox_change= onSpinboxShareCountChanged;
   

    
    /////////////////////////////////////////// Shamir share parameters
    NEW_VBOX(vbox_shamir);
    
    NEW_ROWBOX(status_box);
	CURRENT_TAB.lbl_pki_status    = uiNewLabel(LABEL_PKI_STATUS_LOCKED);
    BOX_APPEND( status_box, uiNewLabel(LABEL_PKI_STATUS), 1);
    BOX_APPEND( status_box, CURRENT_TAB.lbl_pki_status,    0);

	uiGroup* group_share_params = uiNewGroup(LABEL_GROUP_SHARE_PARAMETERS);
	uiGroupSetMargined(group_share_params, 1);
	uiGroupSetChild(group_share_params, uiControl(vbox_shamir));

	

    // Share spinboxes
	CURRENT_TAB.spin_quorum      = uiNewSpinbox( 1, MAX_SHAMIR_SHARE_NUMBER);
    uiSpinboxSetValue( CURRENT_TAB.spin_quorum, s4w->ctx->quorum);
    uiSpinboxOnChanged(CURRENT_TAB.spin_quorum, CURRENT_TAB.on_quorum_spinbox_change, s4w );

    CURRENT_TAB.spin_share_count = uiNewSpinbox( 1, MAX_SHAMIR_SHARE_NUMBER);
    uiSpinboxSetValue( CURRENT_TAB.spin_share_count, s4w->ctx->nb_share);
	uiSpinboxOnChanged(CURRENT_TAB.spin_share_count, CURRENT_TAB.on_share_num_spinbox_change, s4w );

    NEW_BUTTON( CURRENT_TAB.btn_rekey, LABEL_BTN_REKEY, CURRENT_TAB.on_rekey_click );
    
  
    BOX_APPEND( vbox_shamir, uiNewHorizontalSeparator(),    0);
	BOX_APPEND( vbox_shamir, uiNewLabel(LABEL_SHARE_COUNT), 0);
	BOX_APPEND( vbox_shamir, CURRENT_TAB.spin_share_count,  0);
	BOX_APPEND( vbox_shamir, uiNewLabel(LABEL_QUORUM_SIZE), 0);
	BOX_APPEND( vbox_shamir, CURRENT_TAB.spin_quorum,       0);
	BOX_APPEND( vbox_shamir, CURRENT_TAB.btn_rekey,         0);	
	BOX_APPEND( vbox_shamir, uiNewHorizontalSeparator(),    0);


    ////////////////////////////////////////////// Shamir share exports
    NEW_VBOX(vbox_shares_export);

	uiGroup *group_export = uiNewGroup(LABEL_GROUP_SHARE_EXPORT);
	uiGroupSetMargined(group_export, 1);	
	uiGroupSetChild( group_export, uiControl(vbox_shares_export));
    
    CURRENT_TAB.bar_share_export_status = uiNewProgressBar();

    NEW_BUTTON( CURRENT_TAB.btn_export_share, LABEL_BTN_EXPORT_FIRST, CURRENT_TAB.on_export_share_click );

    CURRENT_TAB.lbl_export_progress =  uiNewLabel(LABEL_EXPORT_PROGRESS);
    BOX_APPEND( vbox_shares_export, CURRENT_TAB.lbl_export_progress,   0);
	BOX_APPEND( vbox_shares_export, CURRENT_TAB.bar_share_export_status, 0);
	BOX_APPEND( vbox_shares_export, CURRENT_TAB.btn_export_share,        0);

	/////////////////////////////////////////// Page assembly

	NEW_HBOX(hbox);
	NEW_VBOX(vbox_left);
    NEW_VBOX(vbox_right);

	BOX_APPEND( hbox, vbox_left,  1);
	BOX_APPEND( hbox, vbox_right, 1);

	
   	
    BOX_APPEND( vbox_left, status_box,                    0);
	BOX_APPEND( vbox_left,  group_share_params, 1);

	BOX_APPEND( vbox_right, group_export, 1);

	return uiControl(hbox);
}//eo create_unlock_page



// eof

