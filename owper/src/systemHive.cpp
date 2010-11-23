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

#include "include/systemHive.h"

namespace owper {
    systemHive::systemHive(const char* fileName, int hiveMode/* = HMODE_RO*/):
            hive(fileName, hiveMode) {
        if(this->getType() != HIVE_TYPE_SYSTEM) {
            this->closeHive();
            throw(new owpException("The filename given does not point to a SAM type hive"));
        }

        printf("Default control set: %d\n", this->getDefaultControlSet());
    }

    int systemHive::getDefaultControlSet() {
    	return ntreg::get_dword(this->regHive, 0, (char*)"\\Select\\Default");
    }

    char* systemHive::getBootKey() {
    	int currentControlSet = getDefaultControlSet();
    	char *keyNames[] = {(char*)"JD", (char*)"Skew1", (char*)"GBG", (char*)"Data"};

    	string curKeyPath;
    	char* curClassName;
    	unsigned char unsortedBootKey[0x10] = {0};
    	for(int keyIndex = 0; keyIndex < 4; keyIndex++) {
    		curKeyPath = stringPrintf("\\ControlSet00%d\\Control\\Lsa\\%s",
    								  currentControlSet,
    								  keyNames[keyIndex]
    					 );

    		try {
    			curClassName = this->getClassName((char*)curKeyPath.c_str());
    		} catch(owpException *exception) {
    			//this path is no good - re-throw
    			throw(exception);
    		}

    		sscanf(curClassName, "%x", (int*)(&unsortedBootKey[keyIndex*4]));

    		delete curClassName;
    		curClassName = 0;
    	}

    	printf("Bootkey unsorted: ");
    	for( int i = 0; i < 0x10; i++ )  {
    	    printf("%.2x", unsortedBootKey[i]);
    	}
    	printf("\n");

    	return (char*)NULL;
    }

    char* systemHive::getClassName(char* nkKeyPath) {
    	reg_off nkKeyOffset = this->travPath(0, nkKeyPath, 0);
    	struct ntreg::nk_key *nkKey;

    	try {
    		nkKey = this->getNkKeyAtOffset(nkKeyOffset);
    	}catch(owpException *exception) {
    		//we must have supplied a bad path
    		delete exception;
    		throw(new owpException(stringPrintf("Invalid nk_key path: %s", nkKeyPath)));
    	}

    	char *className = new char[9];
    	int shortestLength = (nkKey->len_classnam > (8 * 2))?(8 * 2):(nkKey->len_classnam);

    	int classNameOffset= nkKey->ofs_classnam + 4;
    	classNameOffset += 0x1000; //this additional offset was taken from bkhive.c:136 (v1.1.1)

    	ntreg::cheap_uni2ascii((char*)(this->regHive->buffer + classNameOffset), className, shortestLength);
    	return className;
    }
}
