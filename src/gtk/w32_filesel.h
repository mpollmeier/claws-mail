/*
 * Sylpheed -- a GTK+ based, lightweight, and fast e-mail client
 * Copyright (C) 1999,2000 Hiroyuki Yamamoto
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

#ifndef __W32_FILESEL_H__
#define __W32_FILESEL_H__

#include <glib.h>

/* emulation */
#define filesel_select_multiple_files_open(x)	filesel_select_multiple_files(x,"")
#define filesel_select_file_save		filesel_select_file
#define filesel_select_file_open		filesel_select_file
#define filesel_select_file_open_folder		filesel_select_file

gchar *filesel_select_file(const gchar *title, const gchar *file);

GList *filesel_select_multiple_files(const gchar *title, const gchar *file);

#endif /* __W32_FILESEL_H__ */
