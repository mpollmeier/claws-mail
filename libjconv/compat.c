
/* $Id: compat.c,v 1.1.2.1 2002-05-11 00:47:52 netztorte Exp $ */

#include <stdio.h>
#include "jconv.h"

#define DEBUG_DO(x)

char *
convert_kanji_auto (const char *src)
{
	return jconv_strdup_conv_fullauto(src);
}

char *
convert_kanji (const char *src, const char *dest_codeset)
{
	return jconv_strdup_conv_autodetect(src, dest_codeset, NULL);
}

char *
convert_kanji_strict (const char *src,
		      const char *dest_codeset,
		      const char *src_codeset)
{
	return jconv_strdup_conv_autodetect(src, dest_codeset, src_codeset,
					    NULL);
}
