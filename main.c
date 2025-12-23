#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "ta152.h"

static void usage (const char *prog) {
    fprintf(stderr, "Usage:\nENCRYPTION: %s encrypt <input_file> <keyfile>\nDECRYPTION: %s decrypt <input_file> <keyfile>\n", prog, prog);
}

static void print_error(int error_code) {
    switch(error_code) {
        case -101: fprintf(stderr, "Error: failed to open file\n"); break;
        case -102: fprintf(stderr, "Error: read failure\n"); break;
        case -103: fprintf(stderr, "Error: write failure\n"); break;
        case -104: fprintf(stderr, "Error: close failure\n"); break;
        case -110: fprintf(stderr, "Error: output path error\n"); break;
        case -111: fprintf(stderr, "Error: invalid key size\n"); break;
        case -112: fprintf(stderr, "Error: key not loaded\n"); break;
        default: fprintf(stderr, "Error: unknown error (%d)\n", error_code); break;
    }
}

int main(int argc, char *argv[])
{
    if (argc != 4) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    const char *mode = argv[1];
    const char *in_path = argv[2];
    const char *key_path = argv[3];

    int rc;

    if (strcmp(mode, "encrypt") == 0) {
        rc = ta152_encrypt(in_path, key_path);
    }
    else if (strcmp(mode, "decrypt") == 0) {
        rc = ta152_decrypt(in_path, key_path);
    }
    else {
        fprintf(stderr, "Error: unknown mode '%s'\n", mode);
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (rc < 0) {
        print_error(rc);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}