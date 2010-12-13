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

#include "include/samHive.h"

namespace owper {
    samHive::samHive(const char* fileName,  unsigned char* bootKey, int hiveMode/* = HMODE_RW*/):
            hive(fileName, hiveMode) {
        if(this->getType() != HIVE_TYPE_SAM) {
            this->closeHive();
            throw(new owpException("The filename given does not point to a SAM type hive"));
        }

        if(bootKey) {
            hashedBootKey = this->getHashedBootKey(bootKey);
        } else {
            hashedBootKey = 0;
        }

        this->loadUserList();
    }

    reg_off samHive::getUserRID(char* userName) {
        string ridPath = stringManip::stringPrintf("\\SAM\\Domains\\Account\\Users\\Names\\%s\\@",userName);
        return this->getDword(0, (char*)ridPath.c_str());
    }

    samUser* samHive::getSamUser(int rid) {
        string vValuePath = stringPrintf("\\SAM\\Domains\\Account\\Users\\%08X\\V",rid);
        ntreg::keyval *vValue = this->copyValueToBuffer(NULL, 0, (char*)vValuePath.c_str(), REG_BINARY);

        samUser *newSamUser;
        try{
            newSamUser = new samUser(rid, vValue, vValuePath, hashedBootKey);
        }catch(owpException e) {
            cerr << e.formattedMessage;
            newSamUser = NULL;
        }

        return newSamUser;
    }

    void samHive::loadUserList() {
        reg_off regKeyOffset = this->travPath(0,(char*)"\\SAM\\Domains\\Account\\Users\\Names\\",0);

        if(!regKeyOffset) {
            throw(new owpException("loadUserList: could not find usernames in registry!"));
        }

        int subKeyCount = 0;
        int subKeyCountRI = 0;
        struct ntreg::ex_data exData;
        string adminUser;
        while((this->getNextSubKey(regKeyOffset+4, &subKeyCount, &subKeyCountRI, &exData) > 0)) {
            //get the RID
            int rid = this->getUserRID(exData.name);

            if(rid == 500) {
                adminUser = exData.name;
            }

            samUser* newSamUser = this->getSamUser(rid);
            if(newSamUser != NULL) {
                this->userList.push_back(newSamUser);
            }

            FREE(exData.name);
        }
    }

    /**
     * Merges changes made with samUser objects back into the hive in memory
     * @return bool Whether or not all changes were merged
     */
    bool samHive::mergeChangesToHive() {
        bool allSuccessful = true;
        for(unsigned int i = 0; i < userList.size(); i++) {
            if(userList.at(i)->needsToSave()) {
                ntreg::keyval *keyValue = userList.at(i)->getVStructRegValue();
                string path = userList.at(i)->getVStructPath().c_str();
                int size = copyBufferToValue(keyValue, 0, (char*)path.c_str(), VAL_TYPE_REG_BINARY);

                if(size < 1) {
                    allSuccessful = false;
                } else {
                    userList.at(i)->hasSaved();
                }

                cout << stringPrintf("Merging into %s: wrote %d bytes", path.c_str(), size) << endl;
            }
        }

        regHive->state |= HMODE_DIRTY;
        return allSuccessful;
    }

    unsigned char* samHive::getFValue() {
        unsigned char* fValue;
        fValue = (unsigned char*)ntreg::get_val_data(this->regHive, 0, (char*)"\\SAM\\Domains\\Account\\F", VAL_TYPE_REG_BINARY);

        if(!fValue) {
            throw(new owpException("No valid F Value found in \\SAM\\Domains\\Account"));
        }

        return fValue;
    }

    unsigned char* samHive::getHashedBootKey(unsigned char* bootKey) {
        unsigned char aqwerty[] = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%";
        unsigned char anum[] = "0123456789012345678901234567890123456789";

        MD5_CTX md5Context;
        unsigned char md5Hash[0x10];
        RC4_KEY rc4Key;
        unsigned char* hashedBootKey = new unsigned char[0x20];

        unsigned char* fValue = this->getFValue();

        MD5_Init(&md5Context);
        MD5_Update(&md5Context, &fValue[0x70], 0x10);
        MD5_Update(&md5Context, aqwerty, 0x2f);
        MD5_Update(&md5Context, bootKey, 0x10);
        MD5_Update(&md5Context, anum, 0x29);
        MD5_Final(md5Hash, &md5Context);
        RC4_set_key(&rc4Key, 0x10, md5Hash);
        RC4(&rc4Key, 0x20, &fValue[0x80], hashedBootKey);

        return hashedBootKey;
    }
}
