/*
 * Common type definitions for MDM
 */

#ifndef TYPES_H
#define TYPES_H

#include <sys/types.h>

#define MAX_NAME 128

typedef struct User {
    char username[MAX_NAME];
    char homedir[256];
    uid_t uid;
} User;

typedef struct Session {
    char name[MAX_NAME];
    char exec[256];
    char type[16];
} Session;

#endif /* TYPES_H */
