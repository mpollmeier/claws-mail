/*
 * Sylpheed -- a GTK+ based, lightweight, and fast e-mail client
 * Copyright (C) 1999-2002 Hiroyuki Yamamoto
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#  include "config.h"
#endif

#include <glib.h>

#include "procmime.h"

struct _PrivacySystem
{
	gchar		*name;
	gboolean	(*is_signed)	(MimeInfo	*mimeinfo);
};

typedef struct _PrivacySystem PrivacySystem;

/* Dummy Test-System Prototypes */
gboolean dummytest_is_signed(MimeInfo *mimeinfo);

PrivacySystem privacysystems[] = {
    /*	{"PGP/MIME", rfc2015_is_signed }, */
    /*	{"PGP/Text", pgptext_is_signed }, */
    /*	{"S/MIME", smime_is_signed }, */
	{ "Dummy", dummytest_is_signed },
	{ NULL,	   NULL },
};

gboolean privacy_mimeinfo_is_signed(MimeInfo *mimeinfo)
{
	PrivacySystem *privacysystem;

	for(privacysystem = privacysystems; privacysystem->name; privacysystem++) {
		if(privacysystem->is_signed != NULL && privacysystem->is_signed(mimeinfo))
			return TRUE;			
	}
	
	return FALSE;
}

gboolean dummytest_is_signed(MimeInfo *mimeinfo)
{
	return TRUE;
}
