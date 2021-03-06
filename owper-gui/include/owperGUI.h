/*
 * This file is part of owper-gui - a graphical front-end to owper
 * Copyright (C) 2010 Matthew Morgan
 *
 * Some code was borrowed/modified from the chntpw project
 * Copyright (c) 1997-2007 Petter Nordahl-Hagen
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
#ifndef OWPER_GUI_H
#define OWPER_GUI_H

#include <gtk/gtk.h>
#include <iostream>
#include <string>
#include <vector>

#include "include/samHive.h"
#include "include/userWidget.h"

using namespace std;
using namespace owper;

class owperGUI
{
    private:
        GtkWidget *winMain;
        GtkWidget *vboxMain;
        GtkWidget *frameSamFile;
        GtkWidget *hboxSamFile;
        GtkWidget *entrySamFile;
        GtkWidget *buttonBrowseSamFile;
        GtkWidget *scrollwinUsers;
        GtkWidget *vboxUsers;
        GtkWidget *hboxCommands;
        GtkWidget *buttonClearPasswords;

        string stringSamFileName;
        samHive  *sam;
        vector<userWidget*> vectUserWidgets;

    public:
        owperGUI(string stringInitHivePath = "");

        static void delete_event(GtkWidget *widget, GdkEvent  *event, gpointer data);
        static void destroy(GtkWidget *widget, gpointer data);
        static void sam_file_browse_event(GtkWidget *widget, gpointer owperGUIInstance);
        bool changeHiveFile(string newFileName);
        void clearUsers();
        void loadUsers();
        static void clearPasswords(GtkWidget *widget, gpointer owperGUIInstance);
};


#endif
