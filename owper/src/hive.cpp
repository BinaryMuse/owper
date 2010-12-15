/*
 * This file is part of owper - a c++ windows password changing library based on chntpw
 * Copyright (C) 2010 Matthew Morgan
 *
 * Some code was borrowed/modified from the chntpw project
 * Copyright (c) 1997-2007 Petter Nordahl-Hagen
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * See file LGPL.txt for the full license.
 *
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
            throw(new owpException(stringPrintf("Failed to open/read hive file: %s", fileName)));
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

    /**
     * Return the nk_key struct pointed too by offset
     * @param reg_off The offset of the nk_key as returned by travPath()
     * @return nk_key A valid nk_key struct
     * @throws owpException if the offset doesn't point to a valid nk_key
     */
    struct ntreg::nk_key *hive::getNkKeyAtOffset(reg_off offset) {
    	reg_off nkOffset = offset + 4;
    	struct ntreg::nk_key *nkKey = (ntreg::nk_key*)(nkOffset + this->regHive->buffer);

    	/* make sure it's really an nk_key
    	   putting this check here will prevent us typing it over and over
    	   every time we access this function */
    	if (nkKey->id != 0x6b6e) {
    		throw(new owpException(stringPrintf("Invalid nk_key offset: 0x%x", (unsigned int)offset)));
    	}

    	return nkKey;
    }

    struct ntreg::keyval *hive::copyValueToBuffer(struct ntreg::keyval *kv, int vofs, char *path, int type) {
        return ntreg::get_val2buf(this->regHive, kv, vofs, path, type);
    }

    /**
     * Copy the data from the supplied registry value object into the actual hive
     * @param keyval* regValue Registry value to copy
     * @param int valueOffset Offset within the value?
     * @param char* path The path to which the value will be copied
     * @param REG_VALUE_TYPE type The type of registry value we'll be copying
     * @return int The number of bytes copied
     */
    int hive::copyBufferToValue(struct ntreg::keyval *regValue, int valueOffset, char *path, REG_VALUE_TYPE type) {
        return ntreg::put_buf2val(this->regHive, regValue, valueOffset, path, type);
    }

    int hive::getDword(int vofs, char* path) {
        return ntreg::get_dword(this->regHive, vofs, path);
    }

    bool hive::writeHiveToFile() {
        int errorsPresent = ntreg::writeHive(this->regHive);

        if(errorsPresent) {
            return false;
        } else {
            return true;
        }
    }
}
