#include <iostream>
#include "include/samHive.h"
#include "include/systemHive.h"

using namespace owper;

int main(int argc, char** argv) {
    samHive *mySam = NULL;
    systemHive *mySys = NULL;

    string samPath = argv[1];
    samPath += "/SAM";

    string sysPath = argv[1];
    sysPath += "/system";

    try {
        mySam = new samHive(samPath.c_str());
        printf("Successfully opened: %s\n", samPath.c_str());

        mySys = new systemHive(sysPath.c_str());
        printf("Successfully opened: %s\n", sysPath.c_str());

        printf("Attempting to get boot key...");
        unsigned char* bootKey = mySys->getBootKey();
        printf("done\n");

        printf("Attempting to get hashed boot key...");
        unsigned char* hashedBootKey = mySam->getHashedBootKey(bootKey);
        printf("done\n");

        for( int i = 0; i < 0x20; i++ )  {
            printf("%.2x", hashedBootKey[i]);
        }
        printf("\n");


    } catch(owpException *exception) {
        printf("%s", exception->what());
        delete exception;
        return 1;
    }
}
