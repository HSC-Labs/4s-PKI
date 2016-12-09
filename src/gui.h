/**
 *
 * \file gui.h
 *
 * \brief User interface management declarations
 *
 *
 * Tous droits réservés Hervé Schauer Consultants 2016 - All rights reserved Hervé Schauer Consultants 2016
 *
 * License: see LICENSE.md file
 *
 */

#if !defined( _S4_GUI_H_ )
#define _S4_GUI_H_


#define LIFE_LEN_STEP (5)

#define KEY_SIZE_STEP (512)

#define MAX_MESSAGE_SIZE (2048)


struct SS4Widgets;

typedef void (*gui_button_click_handler_t)   ( uiButton  *s, void *data );
typedef void (*gui_slider_change_handler_t)  ( uiSlider  *s, void *data );
typedef void (*gui_spinbox_change_handler_t) ( uiSpinbox *s, void *data );
typedef void (*gui_entry_change_handler_t)   ( uiEntry   *s, void *data );

typedef void (*gui_state_transition_handler_t) ( struct SS4Widgets* w );

#define NEW_ROWBOX(box)                  \
    uiBox *(box) = uiNewHorizontalBox(); \
    uiBoxSetPadded( (box), 1)

#define NEW_HBOX(box)                    \
    uiBox *(box) = uiNewHorizontalBox(); \
    uiBoxSetPadded( (box), 1)

#define NEW_VBOX(box)                  \
    uiBox *(box) = uiNewVerticalBox(); \
    uiBoxSetPadded( (box), 1)

#define BOX_APPEND(box,ctrl,x)  \
    uiBoxAppend( (box), uiControl( (ctrl) ), (x))


#define NEW_GROUP(grp,box,label)                 \
        NEW_VBOX(box);                           \
        uiGroup* (grp) = uiNewGroup( (label)  ); \
        uiGroupSetMargined( (grp), 1);           \
        uiGroupSetChild( (grp), uiControl((box)) )

#define NEW_BUTTON(var,label,handler) \
        if(1) { \
            (var) = uiNewButton((label)); \
            uiButtonOnClicked( (var), (handler), s4w ); \
        }


typedef struct SShareSelectorData { 
    uiBox       *row;
    uiEntry     *txt;
    uiButton    *btn;
    unsigned     num;
    struct SS4Widgets   *s4w; 
} s_share_selector_data;

/**
 * \brief Context for 4S Gui
 *  
 *  Structure to store windows and control pointers as well as event handlers
 */
typedef struct SS4Widgets 
{
    s_s4context      *ctx;     // application context
    uiWindow         *mainwin; // main window
    
    struct {
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

        uiSpinbox        *spin_quorum;
        uiSpinbox        *spin_share_count;
    
        uiSlider         *sld_key_size;
        uiEntry          *txt_pki_dir;
        uiButton         *btn_sel_pki_dir;
        uiEntry          *txt_pki_subject;
        uiEntry          *txt_pki_cdp_url;
        uiSlider         *sld_ca_life_len;
        uiSlider         *sld_crl_life_len;

        uiProgressBar    *bar_op_status;
        uiEntry          *txt_op_status;
        uiButton         *btn_run;

        uiMultilineEntry *txt_root_cert; 
    
        uiLabel          *lbl_export_progress;
        uiProgressBar    *bar_share_export_status;
        uiButton         *btn_export_share;

        // GUI Event handlers
        gui_button_click_handler_t    on_sel_pki_root_dir_click;
        gui_button_click_handler_t    on_create_click;
        gui_button_click_handler_t    on_export_share_click;

        gui_spinbox_change_handler_t  on_quorum_spinbox_change; 
        gui_spinbox_change_handler_t  on_share_num_spinbox_change;
        gui_slider_change_handler_t   on_key_size_slider_change;
        gui_slider_change_handler_t   on_crl_life_len_slider_change;
        gui_slider_change_handler_t   on_ca_life_len_slider_change;

        gui_entry_change_handler_t    on_subject_txt_change;
    
        // state transition events handlers
        gui_state_transition_handler_t  on_pki_uninitialized;
        gui_state_transition_handler_t  on_pki_initialized;
        gui_state_transition_handler_t  on_all_secrets_exported;

    } tab_create_pki;

    struct  {
    /*
    PKI Status : LOCKED
    Shamir share parameters            | Shamir share export 
                                       |
    Number of share holders            | Share export progress:   
    [ 5                        ] [-][+]| =============>===============                                  
    Quorum size                        |   
    [ 3                        ] [-][+]|  [ Export share button ]
                                       | 
           [ Redo Shamir share]        | 
                                       |    
    
    */    
        uiLabel          *lbl_pki_status;
        
        uiSpinbox        *spin_quorum;
        uiSpinbox        *spin_share_count;
        uiButton         *btn_rekey;
        
        uiLabel          *lbl_export_progress;
        uiProgressBar    *bar_share_export_status;
        uiButton         *btn_export_share;

        // GUI Event handlers
        gui_button_click_handler_t    on_rekey_click;
        gui_button_click_handler_t    on_export_share_click;

        gui_spinbox_change_handler_t  on_quorum_spinbox_change; 
        gui_spinbox_change_handler_t  on_share_num_spinbox_change;
    
    } tab_rekey_share;

    struct  {
    /*
                                       |
                                       |Keys:
    [ PKI directory ] [pkidir btn]     | 
    -----------------------------------| [ txt keyfile 1  ] [k1 btn]
    Subject: <subject text>            | [ txt keyfile 2  ] [k2 btn]
    Nb Key holders: <lbl_num_holders>  | [ txt keyfile 3  ] [k3 btn]
    Quorum: <lbl_quorum>               | [ txt keyfile 4  ] [k4 btn]
    -----------------------------------| [ txt keyfile 5  ] [k5 btn]
     [unlock btn]     [lock btn]       |
                                       |

    */
        // Widgets
        uiEntry          *txt_pki_dir;
        uiButton         *btn_sel_pki_dir;
        uiLabel          *lbl_pki_subject;
        uiLabel          *lbl_nb_holders;
        uiLabel          *lbl_quorum;
        uiLabel          *lbl_loaded_shares;
        uiButton         *btn_unlock;
        uiButton         *btn_lock;
        uiBox            *box_shares;        

        s_share_selector_data keyfiles[DEFAULT_NB_SHARE];

        // Event handlers
        gui_button_click_handler_t    on_sel_pki_root_dir_click;
        gui_button_click_handler_t    on_lock_click;
        gui_button_click_handler_t    on_unlock_click;

    } tab_open_pki;

    struct {
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
        // Widgets
        uiLabel          *lbl_pki_status;
        uiLabel          *lbl_pki_subject;
        uiLabel          *lbl_subca_count;
        uiLabel          *lbl_revoq_count;
        uiLabel          *lbl_last_CRL_date;

        uiEntry          *txt_revoq_cert_file;
        uiButton         *btn_revoq_cert_file;
        uiButton         *btn_revocate;

        uiEntry          *txt_csr_file;
        uiButton         *btn_csr_file;
        uiButton         *btn_sign;

        uiButton         *btn_gen_crl;

        // Events handlers
        gui_button_click_handler_t    on_sign_click;        
        gui_button_click_handler_t    on_revoke_click;
        gui_button_click_handler_t    on_gen_crl_click;

        gui_button_click_handler_t    on_csr_sel_click;        
        gui_button_click_handler_t    on_cert_sel_click;   
 
        gui_state_transition_handler_t  on_pki_loaded; 

    } tab_pki_operations;

    // global events handlers
    gui_state_transition_handler_t  on_pki_unlocked;     
    gui_state_transition_handler_t  on_pki_locked;    

    // PKI event handlers
    s_s4eventhandlers_t pki_events_handlers;
    
} s_s4widgets;


/**
 *
 * Initialize the GUI subsystem
 * 
 * \param title   Title of the main windows
 * \param w       Largeur initiale de la fenetre
 * \param l       Hauteur initiale de la fenetre
 * \param ctx     Application context structure
 * 
 * \return A pointer to the initialized user interface context
 *
 */
s_s4widgets* s4_init_widgets(const char * title, int w, int l, s_s4context * ctx );

/**
 * Build the GUI controls on the intialized window
 *
 * \param w user interface context
 */
void s4_build_gui( s_s4widgets* w );

/**
 * create the pki creation tab
 */ 
uiControl * create_pki_page ( s_s4widgets * s4w );

/**
 * create the operations tab
 */ 
uiControl *create_operations_page( s_s4widgets * s4w );

/**
 * create the unlocking page
 */
uiControl *create_unlock_page( s_s4widgets * s4w );

/**
 * create the unlocking page
 */
uiControl *create_rekey_page( s_s4widgets * s4w );

#endif
//eof

