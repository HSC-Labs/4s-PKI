// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
/**
 *
 * \file gui_tab_create.c
 *
 * \brief User interface basic functions
 *
 *
 * Tous droits réservés Hervé Schauer Consultants 2016 - All rights reserved Hervé Schauer Consultants 2016
 *
 * License: see LICENSE.md file
 *
 */

#define DEEPDEBUG 1

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

#define CTX_SET(var,val) if(1) { s4w->ctx->var = (val); }
#define CTX_GET(var,val) if(1) { (val) = s4w->ctx->var; }
#define CTX_VAL(var)     (s4w->ctx->var)
#if defined(NDEBUG)
    #define CTX_CPY(var,val,max) if(1) { strlcpy( (s4w->ctx->var), (val), (max)); }
#else
    #define CTX_CPY(var,val,max) if(1) { size_t r = strlcpy( (s4w->ctx->var), (val), (max)); assert(r<=max); r=0; }
#endif

#define CURRENT_TAB s4w->tab_create_pki


/**
 * Check wheter Shamir Share parameters are consistant
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
 * Are the parameters set to create the PKI
 */
#ifdef NDEBUG
inline
#endif
int ready_to_create( s_s4widgets * s4w) 
{
	assert( NULL!=s4w );

	const char * subj = uiEntryText( CURRENT_TAB.txt_pki_subject );
	const char * dir  = uiEntryText( CURRENT_TAB.txt_pki_dir );

	if( strcmp(dir, DEFAULT_PKI_DIR) == 0 ) {
		return 0;
	}

	if( strcmp(subj, DEFAULT_ROOT_SUBJECT) == 0 ) {
		return 0;
	}

	return 1;
}//eo ready_to_create


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

static void onSliderCRLLifeLenChanged( uiSlider* s, void * data)
{
    assert(NULL!=s);
    assert(NULL!=data);
        
    s_s4widgets * s4w = (s_s4widgets*)data;

    // ensuring life len is a multiple of LIFE_LEN_STEP
    int  life = uiSliderValue(s);
    life = life - (life % LIFE_LEN_STEP );
    
    CTX_SET( pki_params.crl_life_len, life );

    uiSliderSetValue( s, life );
}//eo onSliderCRLLifeLenChanged

static void onSliderCALifeLenChanged( uiSlider* s, void * data)
{
    assert(NULL!=s);
    assert(NULL!=data);
        
    s_s4widgets * s4w = (s_s4widgets*)data;

    // ensuring life len is a multiple of LIFE_LEN_STEP
    int  life = uiSliderValue(s);
    life = life - (life % LIFE_LEN_STEP );
    
    CTX_SET( pki_params.ca_life_len, life );

    uiSliderSetValue( s, life );
}//eo onSliderCertLifeLenChanged

/**
 * Event handler for key size change
 */
static void onSliderKeySizeChanged( uiSlider* s, void * data )
{
    assert(NULL!=s);
	assert(NULL!=data);
	    
    s_s4widgets * s4w = (s_s4widgets*)data;

    // ensuring key size is a multiple of KEY_SIZE_STEP
    int ksze = uiSliderValue(s);
    ksze = ksze - (ksze % KEY_SIZE_STEP );
    
    CTX_SET( pki_params.ca_key_size, ksze );   
    uiSliderSetValue( s, ksze );
}//eo onSliderKeySizeChanged

/**
 * Event handler for when directory selection clicked
 */
static void onOpenPKISelDirClicked( uiButton * s, void * data )
{
	assert(NULL!=s);
	assert(NULL!=data);
	    
    s_s4widgets * s4w = (s_s4widgets*)data;

	char *filename = uiSelectDir(s4w->mainwin);
	if ( NULL == filename ) {
		uiEntrySetText( CURRENT_TAB.txt_pki_dir, DEFAULT_PKI_DIR );
		return;
	}
    CTX_CPY( pki_params.root_dir, filename, MAX_FILE_PATH);

	uiEntrySetText(CURRENT_TAB.txt_pki_dir, filename);
    uiFreeText(filename);

    if( ready_to_create(s4w) ) {
    	uiControlEnable( uiControl(CURRENT_TAB.btn_run) );
    }

}//eo onOpenPKISelDirClicked

/**
 * Event handler for when PKI creation button is clicked
 */
static void onCreateClicked( uiButton * s, void * data )
{
    assert(NULL!=s);
	assert(NULL!=data);
	    
    s_s4widgets * s4w = (s_s4widgets*)data;
    s_s4context * s4c = s4w->ctx;
    assert( NULL != s4c );
    
    CTX_CPY( pki_params.subject, uiEntryText( CURRENT_TAB.txt_pki_subject ), MAX_PKI_SUBJECT_LEN );     

    const char * subject = CTX_VAL(pki_params.subject);
    const char * rootdir = CTX_VAL(pki_params.root_dir);

    if( check_pki_subject( subject ) ) {
        uiMsgBox( s4w->mainwin,
            "Incorrect root certificate subject",
    		"The subject of the root certificate has to be in the form:\n/CN=pki_name/OU=organisational_unit/O=Organisation\nor\n/CN=pki_name/DC=domain_component/DC=domain_component/DC=domain_component"
        );
    }

    if( check_pki_root_dir( rootdir ) ) {
        uiErrorBoxPrintf( s4w->mainwin, "Incorrect PKI root directory", "'%s' is not an appropriate directory for the PKI root", rootdir );
    }
    
    gen_pass( s4c->passphrase, MAX_B64_ENC_PASS_SIZE);
    printf("Pass : %s\n",s4c->passphrase);

    if( gen_self_signed( rootdir, &(s4c->pki_params), s4c->passphrase, s4c->nb_share, s4c->quorum,  &(s4w->pki_events_handlers)) ) {
        uiErrorBoxPrintf(s4w->mainwin, "PKI Generation failed", "Unable to initialize the PKI");
        return;
    }

    s4c->secret_unlocked=1;
    
    // loading cert description
    char cert_buffer[16384];
    secure_memzero(cert_buffer, sizeof(cert_buffer));
    ssize_t  res = read_ca_cert_infos( rootdir, cert_buffer, sizeof(cert_buffer) );
    if( res > 0 ) {
        DDEBUG_PRN("onCreateClicked: root certificate: %s", cert_buffer);
        uiMultilineEntrySetText( CURRENT_TAB.txt_root_cert, cert_buffer);
    } else {
        warn("onCreateClicked: failed to read CA cert infos from '%s' (res:%d)", rootdir, res);
    }

    CURRENT_TAB.on_pki_initialized(s4w);
    
    if( s4_split( s4c, &(s4w->pki_events_handlers) ) ) {
        uiErrorBoxPrintf(s4w->mainwin, "Secret splitting failed","Unable to perform Shamir secret splitting");
        return;        
    }    

}//eo onRunClicked

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

static void onSubjectChanged( uiEntry* s, void * data  )
{
	assert(NULL!=s);
	assert(NULL!=data);
	s_s4widgets * s4w = (s_s4widgets*)data;
	if( ready_to_create(s4w) ) {
    	uiControlEnable( uiControl(CURRENT_TAB.btn_run) );
    }
}//eo onSubjectChanged

static void onPKIUninitialized( s_s4widgets * s4w)
{
	assert( NULL!=s4w );
    uiControlDisable( uiControl(CURRENT_TAB.txt_root_cert) );
    uiControlDisable( uiControl(CURRENT_TAB.btn_export_share));

}//eo onPKIInitialized

static void onPKIInitialized( s_s4widgets * s4w)
{
	assert( NULL!=s4w );
    uiControlEnable( uiControl(CURRENT_TAB.txt_root_cert) );
    uiControlEnable( uiControl(CURRENT_TAB.btn_export_share));
}//eo onPKIInitialized

static void onAllSecretsExported( s_s4widgets * s4w)
{
	assert( NULL!=s4w );
    uiControlDisable(uiControl(CURRENT_TAB.btn_export_share));
}// onAllSecretsExported


#undef CTX_SET
#undef CTX_GET
#undef CTX_VAL
#undef CTX_CPY


static void gui_creation_progress_handler( void* data, int pct, const char * msg ) 
{
	assert(NULL!=data);

	s_s4widgets * s4w = (s_s4widgets*)data;

	uiProgressBarSetValue(CURRENT_TAB.bar_op_status, pct);
	uiEntrySetText(CURRENT_TAB.txt_op_status,msg);       
}//eo gui_pki_progress_handler


////////////////////////////////////////////////////////////////
//
/*
    
    PKI parameters:                    | PKI generation
                                       |
    Root certificate subject:          | Operation status:
     [ /CN=something/OU=someorg/O=org ]| [ status text               ]
    CRL distribution point             | =============>===============    
     [ http:// somewhere          ]    | [   Initialize PKI button   ]
    Certificate life length (in days)  |
     --------------[>----------------- |--------------------------------
    CRL life lenght (in days)          | PKI informations
     -------------[>------------------ | Root certificate (PEM):
    RSA root key size (bits)           | +----------------------------+
     ---------------[>---------------- | |                            |
    [/PKI install directory ][ Select ]| |                            |
    -----------------------------------| |                            |
                                       | |                            |
    Shamir share parameters            | +----------------------------+
                                       |
    Number of share holders            |-------------------------------- 
    [ 5                        ] [-][+]| Shamir share export 
                                       |
    Quorum size                        | Share export progress:
    [ 3                        ] [-][+]| =============>===============  
    -----------------------------------|    [ Export share button ]
*/
uiControl * create_pki_page ( s_s4widgets * s4w )
{
	assert( NULL!=s4w );

    ////////////////////////////////////////// Event handlers

    // application event handlers
    s4w->pki_events_handlers.on_progress    = gui_creation_progress_handler;
	
	// associating ui event handlers
    CURRENT_TAB.on_all_secrets_exported     = onAllSecretsExported;
    CURRENT_TAB.on_create_click             = onCreateClicked;
    CURRENT_TAB.on_export_share_click       = onExportShareClicked;
    CURRENT_TAB.on_key_size_slider_change   = onSliderKeySizeChanged;
    CURRENT_TAB.on_crl_life_len_slider_change  = onSliderCRLLifeLenChanged;
    CURRENT_TAB.on_ca_life_len_slider_change = onSliderCALifeLenChanged,

    CURRENT_TAB.on_subject_txt_change       = onSubjectChanged;
    CURRENT_TAB.on_pki_initialized          = onPKIInitialized;
    CURRENT_TAB.on_pki_uninitialized        = onPKIUninitialized;
    CURRENT_TAB.on_quorum_spinbox_change    = onSpinboxQuorumChanged;
    CURRENT_TAB.on_sel_pki_root_dir_click   = onOpenPKISelDirClicked;
    CURRENT_TAB.on_share_num_spinbox_change = onSpinboxShareCountChanged;
    
    ///////////////////////////////////////////////////// PKI parameters
    NEW_VBOX(vbox_pki);

	uiGroup* group_params = uiNewGroup(LABEL_GROUP_PKI_PARAMETERS);
	uiGroupSetMargined(group_params, 1);
	uiGroupSetChild(group_params, uiControl(vbox_pki));

    // PKI Common name
    CURRENT_TAB.txt_pki_subject = uiNewEntry();
    uiEntrySetText( CURRENT_TAB.txt_pki_subject, DEFAULT_ROOT_SUBJECT);
    uiEntryOnChanged( CURRENT_TAB.txt_pki_subject, CURRENT_TAB.on_subject_txt_change, s4w );

    // PKI CRL distribution point
    CURRENT_TAB.txt_pki_cdp_url = uiNewEntry();
    uiEntrySetText( CURRENT_TAB.txt_pki_cdp_url, DEFAULT_ROOT_CDP);

    // Certificates (SubCA) life in days
    CURRENT_TAB.sld_ca_life_len = uiNewSlider( MIN_CERT_LIFE_DAYS, MAX_CERT_LIFE_DAYS );
    uiSliderSetValue( CURRENT_TAB.sld_ca_life_len, s4w->ctx->pki_params.ca_life_len );
    uiSliderOnChanged( CURRENT_TAB.sld_ca_life_len, CURRENT_TAB.on_ca_life_len_slider_change, s4w );

    // CRL (SubCA) life in days
    CURRENT_TAB.sld_crl_life_len = uiNewSlider( MIN_CRL_LIFE_DAYS, MAX_CRL_LIFE_DAYS );
    uiSliderSetValue( CURRENT_TAB.sld_crl_life_len, s4w->ctx->pki_params.crl_life_len );
    uiSliderOnChanged( CURRENT_TAB.sld_crl_life_len, CURRENT_TAB.on_crl_life_len_slider_change, s4w );


    // PKI root key size
    CURRENT_TAB.sld_key_size = uiNewSlider( MIN_KEY_SIZE, MAX_KEY_SIZE);
    uiSliderSetValue( CURRENT_TAB.sld_key_size, s4w->ctx->pki_params.ca_key_size );
    uiSliderOnChanged( CURRENT_TAB.sld_key_size, CURRENT_TAB.on_key_size_slider_change, s4w );

    // PKI root directory selection

	NEW_BUTTON( CURRENT_TAB.btn_sel_pki_dir, LABEL_SELECT_ROOT_DIR, CURRENT_TAB.on_sel_pki_root_dir_click );

    CURRENT_TAB.txt_pki_dir = uiNewEntry();
    uiEntrySetText(CURRENT_TAB.txt_pki_dir , DEFAULT_PKI_DIR);
	uiEntrySetReadOnly(CURRENT_TAB.txt_pki_dir, 1);

    NEW_ROWBOX( dir_box );

	BOX_APPEND( dir_box, CURRENT_TAB.txt_pki_dir , 1);
    BOX_APPEND( dir_box, CURRENT_TAB.btn_sel_pki_dir, 0);
    
    BOX_APPEND( vbox_pki, uiNewLabel(LABEL_ROOT_SUBJECT), 0);
    BOX_APPEND( vbox_pki, CURRENT_TAB.txt_pki_subject, 0);
    
    BOX_APPEND( vbox_pki, uiNewLabel(LABEL_ROOT_CDP), 0);
    BOX_APPEND( vbox_pki, CURRENT_TAB.txt_pki_cdp_url, 0);
   
    BOX_APPEND( vbox_pki, uiNewLabel(LABEL_CERT_LIFE_DAYS), 0);
    BOX_APPEND( vbox_pki, CURRENT_TAB.sld_ca_life_len, 0);

    BOX_APPEND( vbox_pki, uiNewLabel(LABEL_CRL_LIFE_DAYS), 0);
    BOX_APPEND( vbox_pki, CURRENT_TAB.sld_crl_life_len, 0);

    BOX_APPEND( vbox_pki, uiNewLabel(LABEL_ROOT_KEYSIZE), 0);
    BOX_APPEND( vbox_pki, CURRENT_TAB.sld_key_size, 0 );
	
    BOX_APPEND( vbox_pki, dir_box, 0 );
    BOX_APPEND( vbox_pki, uiNewHorizontalSeparator(), 0 );
    
    /////////////////////////////////////////// Shamir share parameters
    NEW_VBOX(vbox_shamir);

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

	BOX_APPEND( vbox_shamir, uiNewLabel(LABEL_SHARE_COUNT), 0);
	BOX_APPEND( vbox_shamir, CURRENT_TAB.spin_share_count,  0);
	BOX_APPEND( vbox_shamir, uiNewLabel(LABEL_QUORUM_SIZE), 0);
	BOX_APPEND( vbox_shamir, CURRENT_TAB.spin_quorum,       0);
	BOX_APPEND( vbox_shamir, uiNewHorizontalSeparator(),    0);

    //////////////////////////////////////////////////////// Operations
    NEW_VBOX(vbox_operations);

	uiGroup* group_gen = uiNewGroup(LABEL_GROUP_GENERATION);
	uiGroupSetMargined(group_gen, 1);
	uiGroupSetChild(group_gen, uiControl(vbox_operations));

    CURRENT_TAB.txt_op_status = uiNewEntry();
	uiEntrySetReadOnly(CURRENT_TAB.txt_op_status, 1);
	uiEntrySetText( CURRENT_TAB.txt_op_status, s4w->ctx->op_status );

    CURRENT_TAB.bar_op_status = uiNewProgressBar();

	NEW_BUTTON( CURRENT_TAB.btn_run, LABEL_BTN_CREATE, CURRENT_TAB.on_create_click );

    BOX_APPEND( vbox_operations, uiNewLabel(LABEL_OP_STATUS), 0);
    BOX_APPEND( vbox_operations, CURRENT_TAB.txt_op_status,   0);
	BOX_APPEND( vbox_operations, CURRENT_TAB.bar_op_status,   0);
	BOX_APPEND( vbox_operations, CURRENT_TAB.btn_run,         0);
    BOX_APPEND( vbox_operations, uiNewHorizontalSeparator(),  0);

    /////////////////////////////////////////////////// PKI information
    NEW_VBOX(vbox_pki_info);
    
	uiGroup* group_info = uiNewGroup(LABEL_GROUP_PKI_INFO);
	uiGroupSetMargined(group_info, 1);	
	uiGroupSetChild(group_info, uiControl(vbox_pki_info));

    CURRENT_TAB.txt_root_cert = uiNewMultilineEntry();
    uiMultilineEntrySetReadOnly(CURRENT_TAB.txt_root_cert, 1);
	uiMultilineEntrySetText( CURRENT_TAB.txt_root_cert, DEFAULT_CERT_CONTENT);

    BOX_APPEND( vbox_pki_info, uiNewLabel(LABEL_CERT_FNAME), 0);
	BOX_APPEND( vbox_pki_info, CURRENT_TAB.txt_root_cert,    2);
    BOX_APPEND( vbox_pki_info, uiNewHorizontalSeparator(),   0);

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

	uiControlDisable( uiControl(CURRENT_TAB.btn_run) );

	/////////////////////////////////////////// Page assembly

	NEW_HBOX(hbox);
	NEW_VBOX(vbox_left);
    NEW_VBOX(vbox_right);

	BOX_APPEND( hbox, vbox_left,  1);
	BOX_APPEND( hbox, vbox_right, 1);

	BOX_APPEND( vbox_left,  group_params,       1);
	BOX_APPEND( vbox_left,  group_share_params, 1);

	BOX_APPEND( vbox_right, group_gen,          1);
	BOX_APPEND( vbox_right, group_info, 1);
	BOX_APPEND( vbox_right, group_export, 1);

    ////////////////
	return uiControl(hbox);
}//eo create_pki_page





//eof

