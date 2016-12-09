// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com
/**
 *
 * \file ui_ext.c
 *
 * \brief Extension to libui library implementation
 *
 *
 * Tous droits réservés Hervé Schauer Consultants 2016 - All rights reserved Hervé Schauer Consultants 2016
 *
 * License: see LICENSE.md file
 *
 */

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>


#include "ui_ext.h"

static const unsigned message_buffer_size = 255;

void uiMsgBoxPrintf( uiWindow *parent, const char *title, const char * fmt, ... )
{
 	va_list args;
	va_start (args, fmt);

 	char message[message_buffer_size];

	vsnprintf( message, sizeof(message)-1, fmt, args);
	message[message_buffer_size]='\0';

 	uiMsgBox( parent, title, message );
 }//eo uiMsgBoxPrintf


 void uiErrorBoxPrintf( uiWindow *parent, const char *title, const char * fmt, ... )
 {
 	va_list args;
	va_start (args, fmt);

 	char message[message_buffer_size];

	vsnprintf( message, sizeof(message)-1, fmt, args);
	message[message_buffer_size]='\0';
	
 	uiMsgBoxError( parent, title, message );
 }//eo uiErrorBoxPrintf




#if defined(__linux__)
//////////////////////////////////////////////////////// Linux specific

//include <gtk/gtk.h>


#if 0
static char *filedialog(GtkWindow *parent, GtkFileChooserAction mode, const gchar *confirm)
{
	GtkWidget *fcd;
	GtkFileChooser *fc;
	gint response;
	char *filename;

	fcd = gtk_file_chooser_dialog_new(NULL, parent, mode,
		"_Cancel", GTK_RESPONSE_CANCEL,
		confirm, GTK_RESPONSE_ACCEPT,
		NULL);
	fc = GTK_FILE_CHOOSER(fcd);
	gtk_file_chooser_set_local_only(fc, FALSE);
	gtk_file_chooser_set_select_multiple(fc, FALSE);
	gtk_file_chooser_set_show_hidden(fc, TRUE);
	gtk_file_chooser_set_do_overwrite_confirmation(fc, TRUE);
	gtk_file_chooser_set_create_folders(fc, TRUE);
	response = gtk_dialog_run(GTK_DIALOG(fcd));
	if (response != GTK_RESPONSE_ACCEPT) {
		gtk_widget_destroy(fcd);
		return NULL;
	}
	filename = uiUnixStrdupText(gtk_file_chooser_get_filename(fc));
	gtk_widget_destroy(fcd);
	return filename;
}

char* uiSelectDir(uiWindow *parent)
{
    return filedialog( windowWindow(parent), GTK_FILE_CHOOSER_ACTION_SELECT_FOLDER, "_Open");
}
#endif

#elif defined(_WIN32_)
////////////////////////////////////////////////////// Windows specific

#if 0
char *commonItemDialog(HWND parent, REFCLSID clsid, REFIID iid, FILEOPENDIALOGOPTIONS optsadd)
{
	IFileDialog *d = NULL;
	FILEOPENDIALOGOPTIONS opts;
	IShellItem *result = NULL;
	WCHAR *wname = NULL;
	char *name = NULL;
	HRESULT hr;

	hr = CoCreateInstance(clsid,
		NULL, CLSCTX_INPROC_SERVER,
		iid, (LPVOID *) (&d));
	if (hr != S_OK) {
		logHRESULT(L"error creating common item dialog", hr);
		// always return NULL on error
		goto out;
	}
	hr = d->GetOptions(&opts);
	if (hr != S_OK) {
		logHRESULT(L"error getting current options", hr);
		goto out;
	}
	opts |= optsadd;
	// the other platforms don't check read-only; we won't either
	opts &= ~FOS_NOREADONLYRETURN;
	hr = d->SetOptions(opts);
	if (hr != S_OK) {
		logHRESULT(L"error setting options", hr);
		goto out;
	}
	hr = d->Show(parent);
	if (hr == HRESULT_FROM_WIN32(ERROR_CANCELLED))
		// cancelled; return NULL like we have ready
		goto out;
	if (hr != S_OK) {
		logHRESULT(L"error showing dialog", hr);
		goto out;
	}
	hr = d->GetResult(&result);
	if (hr != S_OK) {
		logHRESULT(L"error getting dialog result", hr);
		goto out;
	}
	hr = result->GetDisplayName(SIGDN_FILESYSPATH, &wname);
	if (hr != S_OK) {
		logHRESULT(L"error getting filename", hr);
		goto out;
	}
	name = toUTF8(wname);

out:
	if (wname != NULL)
		CoTaskMemFree(wname);
	if (result != NULL)
		result->Release();
	if (d != NULL)
		d->Release();
	return name;
}

char * uiSelectDir( uiWindow * parent ) 
{
    char *res;

	disableAllWindowsExcept(parent);
	res = commonItemDialog(windowHWND(parent),
		CLSID_FileOpenDialog, IID_IFileOpenDialog,
		FOS_NOCHANGEDIR | FOS_ALLNONSTORAGEITEMS | FOS_NOVALIDATE | FOS_PATHMUSTEXIST | FOS_PICKFOLDERS | FOS_SHAREAWARE | FOS_NOTESTFILECREATE | FOS_NODEREFERENCELINKS | FOS_FORCESHOWHIDDEN | FOS_DEFAULTNOMINIMODE);
	enableAllWindowsExcept(parent);
	return res;

}
#endif

#endif 
///////////////////////////////////////////////////////////////////////