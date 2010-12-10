#ifndef HELPERS_H
#define HELPERS_H

#define DELETE_IF_DEFINED(PTR) \
    \
    if((PTR)) { \
        delete (PTR); \
    } \

#endif
