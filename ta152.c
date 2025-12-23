#define _GNU_SOURCE
#include <stdlib.h>
#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include "ta152.h"

#define SUCCESS_ENCRYPT 101
#define SUCCESS_DECRYPT 102

#define ERR_OPEN_FAILED -101
#define ERR_NO_READ -102
#define ERR_NO_WRITE -103
#define ERR_CLOSE_FAILED -104
#define ERR_NO_PATH_OUT -110
#define ERR_INVALID_KEY_SIZE -111
#define ERR_KEY_NOT_LOADED -112

#define MATRIX_LEN 256
#define KEY_SIZE 16

// open for read
static int fd_open_read(const char *path) {
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return ERR_OPEN_FAILED;
    return fd;
}

// open for write
static int fd_open_write (const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return ERR_OPEN_FAILED;
    return fd;
}

// write at path, upto len bytes
static int write_all(int fd, const void *buffer, size_t len)
{
    const uint8_t *p = buffer;
    while (len > 0) {
        ssize_t w = write(fd, p, len);
        if (w < 0)
            return ERR_NO_WRITE;
        if (w == 0)
            continue;
        p   += w;
        len -= w;
    }
    return 0;
}

// basic read wrapper
static ssize_t fd_read(int fd, void *buf, size_t maxlen)
{
    ssize_t r = read(fd, buf, maxlen);
    if (r < 0)
        return ERR_NO_READ;
    return r;
}

//close file at file descriptor
static int fd_close(int fd)
{
    int r = close(fd);
    if (r != 0)
        return ERR_CLOSE_FAILED;
    return 0;
}

static inline void swap_mx(uint8_t *base_mx, uint8_t *inverse_mx, int a, int b) {
    uint8_t x = base_mx[a];
    uint8_t y = base_mx[b];

    base_mx[a] = y;
    base_mx[b] = x;

    inverse_mx[x] = b;
    inverse_mx[y] = a;
}

void init_matrix(uint8_t base_mx[MATRIX_LEN]) {
    for (int i = 0; i < MATRIX_LEN; i++) {
        *(base_mx + i) = (uint8_t) i;
    }
}

void ta152_round(uint8_t key, uint8_t *base_mx, uint8_t *inverse_mx) {
    
    int chunk_size;
    if (key == 0 || key == 1)
        chunk_size = 2;
    else
        chunk_size = (int)key;

//    uint8_t x, y;

    int offset = 0;
    while (offset + chunk_size <= MATRIX_LEN) {
        for (int i = 0; i < chunk_size / 2; i++) {
            int a = offset + i;
            int b = offset + chunk_size - 1 - i;

            swap_mx(base_mx, inverse_mx, a, b);
        }
        offset += chunk_size;
    }

    int leftover = MATRIX_LEN - offset;
    if (leftover > 1) {
        for (int i = 0; i < leftover / 2; i++) {
            int a = offset + i;
            int b = offset + leftover - 1 - i;

            swap_mx(base_mx, inverse_mx, a, b);
        }
    }
}

uint8_t ta152_encrypt_chunk(uint8_t input_chunk, uint8_t key_byte, uint8_t *base_mx, uint8_t *inverse_mx) {
        int pos = (int)input_chunk;
        ta152_round(key_byte, base_mx, inverse_mx);
        return *(base_mx + pos);
}

uint8_t ta152_decrypt_chunk(uint8_t input_chunk, uint8_t key_byte, uint8_t *base_mx, uint8_t *inverse_mx) {
    int pos = (int) input_chunk;
    ta152_round(key_byte, base_mx, inverse_mx);
    return *(inverse_mx + pos);
}

int ta152_encrypt(const char *in_path, const char *key_file) {
    size_t in_path_len = strlen(in_path);
    char *out_path = malloc(sizeof(char) * (in_path_len + 7));
    if (!out_path)
        return ERR_NO_PATH_OUT;
    strcpy(out_path, in_path);
    strcat(out_path, ".t152e");

    uint8_t *key_mx = malloc(sizeof(uint8_t) * KEY_SIZE);
    if (!key_mx) {
        free(out_path);
        return ERR_KEY_NOT_LOADED;
    }
    int keypos = 0;

    uint8_t base_mx[MATRIX_LEN];
    uint8_t inverse_mx[MATRIX_LEN];

    init_matrix(base_mx);
    init_matrix(inverse_mx);

    int in_file = fd_open_read(in_path);
    if (in_file < 0) {
        free(out_path);
        explicit_bzero(key_mx, KEY_SIZE); 
        free(key_mx);
        return ERR_OPEN_FAILED;
    }

    int out_file = fd_open_write(out_path);
    if (out_file < 0) {
        free(out_path);
        explicit_bzero(key_mx, KEY_SIZE); 
        free(key_mx);
        return ERR_OPEN_FAILED;
    }

    int key_d = fd_open_read(key_file);
    if (key_d < 0) {
        free(out_path);
        explicit_bzero(key_mx, KEY_SIZE); 
        free(key_mx);
        fd_close(in_file);
        fd_close(out_file);
        return ERR_OPEN_FAILED;
    }

    ssize_t key_bytes = fd_read(key_d, key_mx, KEY_SIZE);
    if (key_bytes != KEY_SIZE) {
        fd_close(in_file);
        fd_close(out_file); 
        fd_close(key_d);
        free(out_path);
        explicit_bzero(key_mx, KEY_SIZE); 
        free(key_mx);
        return ERR_INVALID_KEY_SIZE;
    }

    fd_close(key_d);

    uint8_t inbuf[4096];
    uint8_t outbuf[4096];
    size_t outpos = 0;

    while (1) {
        ssize_t bytes_read = read(in_file, inbuf, sizeof inbuf);

        if (bytes_read == 0) {
            break; //EOF
        }

        if (bytes_read < 0) {
            explicit_bzero(key_mx, KEY_SIZE);
            free(key_mx);
            free(out_path);
            fd_close(in_file);
            fd_close(out_file);
            return ERR_NO_READ;
        }

        for (ssize_t i = 0; i < bytes_read; i++) {
            uint8_t cipher =
                ta152_encrypt_chunk(inbuf[i], key_mx[keypos], base_mx, inverse_mx);

            outbuf[outpos++] = cipher;
            keypos = (keypos + 1) % KEY_SIZE;

            if (outpos == sizeof outbuf) {
                if (write_all(out_file, outbuf, outpos) < 0) {
                    explicit_bzero(key_mx, KEY_SIZE);
                    free(key_mx);
                    free(out_path);
                    fd_close(in_file);
                    fd_close(out_file);
                    return ERR_NO_WRITE;
                }
                outpos = 0;
            }
        }
    }

// flush tail
    if (outpos > 0) {
        if (write_all(out_file, outbuf, outpos) < 0) {
            explicit_bzero(key_mx, KEY_SIZE);
            free(key_mx);
            free(out_path);
            fd_close(in_file);
            fd_close(out_file);
            return ERR_NO_WRITE;
        }
    }    

    free(out_path);
    explicit_bzero(key_mx, KEY_SIZE); 
    free(key_mx);
    fd_close(in_file);
    fd_close(out_file);
    return SUCCESS_ENCRYPT;
}

int ta152_decrypt(const char *in_path, const char *key_file) {
    size_t in_path_len = strlen(in_path);
    char extension[7];
    char *out_path = NULL;
    if (in_path_len > 6) {
        strcpy(extension, in_path + in_path_len - 6);

        if (strcmp(extension, ".t152e") == 0) {
            out_path = malloc(in_path_len - 6 + 1);
            if (!out_path) 
                return ERR_NO_PATH_OUT;

            strncpy(out_path, in_path, in_path_len - 6);
            out_path[in_path_len - 6] = '\0';
        }
    }

    if (!out_path) {
        out_path = malloc(in_path_len + 1);
        if (!out_path)
            return ERR_NO_PATH_OUT;
        strcpy(out_path, in_path);
    }

    uint8_t *key_mx = malloc(sizeof(uint8_t) * KEY_SIZE);
    if (!key_mx) {
        free(out_path);
        return ERR_KEY_NOT_LOADED;
    }
    int keypos = 0;

    uint8_t base_mx[MATRIX_LEN];
    uint8_t inverse_mx[MATRIX_LEN];

    init_matrix(base_mx);
    init_matrix(inverse_mx);

    int in_file = fd_open_read(in_path);
    if (in_file < 0) {
        free(out_path);
        explicit_bzero(key_mx, KEY_SIZE); 
        free(key_mx);
        return ERR_OPEN_FAILED;
    }

    int out_file = fd_open_write(out_path);
    if (out_file < 0) {
        free(out_path);
        explicit_bzero(key_mx, KEY_SIZE); 
        free(key_mx);
        return ERR_OPEN_FAILED;
    }

    int key_d = fd_open_read(key_file);
    if (key_d < 0) {
        free(out_path);
        explicit_bzero(key_mx, KEY_SIZE); 
        free(key_mx);
        fd_close(in_file);
        fd_close(out_file);
        return ERR_OPEN_FAILED;
    }

    ssize_t key_bytes = fd_read(key_d, key_mx, KEY_SIZE);
    if (key_bytes != KEY_SIZE) {
        fd_close(in_file);
        fd_close(out_file); 
        fd_close(key_d);
        free(out_path);
        explicit_bzero(key_mx, KEY_SIZE); 
        free(key_mx);
        return ERR_INVALID_KEY_SIZE;
    }

    fd_close(key_d);

    uint8_t inbuf[4096];
    uint8_t outbuf[4096];
    size_t outpos = 0;

    while (1) {
        ssize_t bytes_read = read(in_file, inbuf, sizeof inbuf);

        if (bytes_read == 0) {
            break; //EOF
        }

        if (bytes_read < 0) {
            explicit_bzero(key_mx, KEY_SIZE);
            free(key_mx);
            free(out_path);
            fd_close(in_file);
            fd_close(out_file);
            return ERR_NO_READ;
        }

        for (ssize_t i = 0; i < bytes_read; i++) {
            uint8_t plain =
                ta152_decrypt_chunk(inbuf[i], key_mx[keypos], base_mx, inverse_mx);

            outbuf[outpos++] = plain;
            keypos = (keypos + 1) % KEY_SIZE;

            if (outpos == sizeof outbuf) {
                if (write_all(out_file, outbuf, outpos) < 0) {
                    explicit_bzero(key_mx, KEY_SIZE);
                    free(key_mx);
                    free(out_path);
                    fd_close(in_file);
                    fd_close(out_file);
                    return ERR_NO_WRITE;
                }
                outpos = 0;
            }
        }
    }

// flush tail
    if (outpos > 0) {
        if (write_all(out_file, outbuf, outpos) < 0) {
            explicit_bzero(key_mx, KEY_SIZE);
            free(key_mx);
            free(out_path);
            fd_close(in_file);
            fd_close(out_file);
            return ERR_NO_WRITE;
        }
    }  
    
    free(out_path);
    explicit_bzero(key_mx, KEY_SIZE); 
    free(key_mx);
    fd_close(in_file);
    fd_close(out_file);
    return SUCCESS_DECRYPT;
}