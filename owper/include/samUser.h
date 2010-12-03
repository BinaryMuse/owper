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

#ifndef SAM_USER_H
#define SAM_USER_H

#include <iostream>
#include <cstdlib>
#include <string>
#include <cstring>

#include <openssl/md5.h>
#include <openssl/rc4.h>
#include <openssl/des.h>

#include "include/ntreg.h"
#include "include/sam.h"
#include "include/binaryManip.h"
#include "include/owpException.h"

using std::string;

namespace owper {
    class samUser {
    private:
        int            rid;
        string         userName;
        string         fullName;
        unsigned char *hashedBootKey;
        unsigned char *lmHash;
        //unsigned char *ntHash;
        string         vStructPath;
        char*          vBuffer;
        ntreg::keyval *vStructRegValue;
        ntreg::user_V *vStruct;
        bool           hasBlankPassword;
        bool           regDataChanged;

        bool   hasValidVStructData(ntreg::keyval *vValue);
        bool   hasValidUserName(int userNameOffset, int userNameLength, int vStructLength);
        bool   hasValidFullName(int fullNameOffset, int fullNameLength, int vStructlength);
        string getUserValue(char* dataBuffer, int valueOffset, int valueLength);

    public:
        /* syskey related functions */
        void calcLMHash();
        bool lmHashIsEmpty();
        void ridToKey1(unsigned long rid, unsigned char deskey[8]);
        void ridToKey2(unsigned long rid, unsigned char deskey[8]);
        void strToDesKey(unsigned char *str, unsigned char *key);

    public:
        samUser(int inRid, ntreg::keyval *inVStructRegValue, string inVStructPath, unsigned char* hashedBootKey);
        ~samUser();
        void blankPassword();

        string getFullName() const
        {
            return fullName;
        }

        string getUserName() const
        {
            return userName;
        }

        bool passwordIsBlank() const
        {
            return hasBlankPassword;
        }

        bool needsToSave() const
        {
            return regDataChanged;
        }

        void hasSaved() {
            regDataChanged = false;
        }

        string getVStructPath() const
        {
            return vStructPath;
        }

        ntreg::keyval *getVStructRegValue() {
            return vStructRegValue;
        }
    };
}

#endif
