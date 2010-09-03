/*
 * This file is part of owper - a graphical version of the well known chntpw password changer
 * Copyright (C) 2010 Matthew Morgan
 *
 * Some code was borrowed/modified from the chntpw project
 * Copyright (c) 1997-2007 Petter Nordahl-Hagen
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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

#include "include/hive.h"
#include "include/owpException.h"

using std::cout;
using std::cerr;
using std::endl;

namespace owper {
    hive::hive(const char* fileName, int hiveMode/* = HMODE_RW*/) {
        this->openHive(fileName, hiveMode);
    }

    void hive::openHive(const char* fileName, int hiveMode) {
        if((this->regHive = ntreg::openHive((char *)fileName, hiveMode)) == NULL) {
            //ntreg::openHive automatically calls closeHive on failure
            throw(owpException(stringPrintf("Failed to open/read hive file: %s", fileName)));
        }
    }

    void hive::closeHive() {
        if(this->regHive != NULL) {
            ntreg::closeHive(this->regHive);
            this->regHive = NULL;
        }
    }

    hive::~hive() {
        closeHive();
    }

    reg_off hive::travPath(reg_off startingOffset, char* path, int type) {
        return ntreg::trav_path(this->regHive, startingOffset, path, type);
    }

    SCAN_KEY_RESULT hive::getNextSubKey(int nkofs, int *count, int *countri, struct ntreg::ex_data *sptr) {
        return (SCAN_KEY_RESULT)ntreg::ex_next_n(this->regHive, nkofs, count, countri, sptr);
    }

    struct ntreg::keyval *hive::copyValueToBuffer(struct ntreg::keyval *kv, int vofs, char *path, int type) {
        return ntreg::get_val2buf(this->regHive, kv, vofs, path, type);
    }

    int hive::getDword(int vofs, char* path) {
        return ntreg::get_dword(this->regHive, vofs, path);
    }

    void hive::unicodeToAscii(char *src, char*dest, int l) {
        ntreg::cheap_uni2ascii(src, dest, l);
    }

    void hive::asciiToUnicode(char *src, char*dest, int l) {
        ntreg::cheap_ascii2uni(src, dest, l);
    }
}
