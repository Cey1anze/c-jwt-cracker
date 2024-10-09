/*

Copyright (c) 2017 Brendan Rius. All rights reserved

Configurable HMAC hash functions implemented in 2021 by Maxim Masiutin,
see the "README.md" file for more details.

*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdbool.h>
#include <pthread.h>
#include "base64.h"

char *g_header_b64 = NULL; // Holds the Base64 header of the original JWT
char *g_payload_b64 = NULL; // Holds the Base64 payload of the original JWT
char *g_signature_b64 = NULL; // Holds the Base64 signature of the original JWT
unsigned char *g_to_encrypt = NULL; // Holds the part of the JWT that needs to be hashed
unsigned char *g_signature = NULL; // Holds the Base64 *decoded* signature of the original JWT

size_t g_header_b64_len = 0;
size_t g_payload_b64_len = 0;
size_t g_signature_b64_len = 0;
size_t g_signature_len = 0;
size_t g_to_encrypt_len = 0;

char *g_alphabet = NULL;
size_t g_alphabet_len = 0;

char *g_found_secret = NULL;
char **g_dict = NULL;
size_t g_dict_size = 0;

struct s_thread_data {
    const EVP_MD *g_evp_md;
    unsigned char *g_result;
    unsigned int g_result_len;
    char *g_buffer;
    char starting_letter;
    size_t max_len;
};

void init_thread_data(struct s_thread_data *data, char starting_letter, size_t max_len, const EVP_MD *evp_md) {
    data->max_len = max_len;
    data->starting_letter = starting_letter;
    data->g_evp_md = evp_md;
    data->g_result = malloc(EVP_MAX_MD_SIZE);
    data->g_buffer = malloc(max_len + 1);
}

void destroy_thread_data(struct s_thread_data *data) {
    free(data->g_result);
    free(data->g_buffer);
}

bool check(struct s_thread_data *data, const char *secret, size_t secret_len) {
    if (g_found_secret != NULL) {
        destroy_thread_data(data);
        pthread_exit(NULL);
    }

    HMAC(
            data->g_evp_md,
            (const unsigned char *) secret, secret_len,
            (const unsigned char *) g_to_encrypt, g_to_encrypt_len,
            data->g_result, &(data->g_result_len)
    );

    return memcmp(data->g_result, g_signature, g_signature_len) == 0;
}

bool brute_impl(struct s_thread_data *data, char* str, int index, int max_depth) {
    for (int i = 0; i < g_alphabet_len; ++i) {
        str[index] = g_alphabet[i];

        if (index == max_depth - 1) {
            if (check(data, (const char *) str, max_depth)) return true;
        } else {
            if (brute_impl(data, str, index + 1, max_depth)) return true;
        }
    }

    return false;
}

char *brute_sequential(struct s_thread_data *data) {
    data->g_buffer[0] = data->starting_letter;
    if (check(data, data->g_buffer, 1)) {
        g_found_secret = strndup(data->g_buffer, 1);
        return g_found_secret;
    }

    for (size_t i = 2; i <= data->max_len; ++i) {
        if (brute_impl(data, data->g_buffer, 1, i)) {
            g_found_secret = strndup(data->g_buffer, i);
            return g_found_secret;
        }
    }
    return NULL;
}

void usage(const char *cmd) {
    printf("Usage: %s -t <token> [-a <alphabet>] [-m <max_len>] [-h <hmac_alg>] [-d <dictionary_file>]\n"
           "Options:\n"
           "  -t, --token              JWT token to brute force\n"
           "  -a, --alphabet           Custom alphabet (default: \"eariotnslcudpmhgbfywkvxzjqEARIOTNSLCUDPMHGBFYWKVXZJQ0123456789\")\n"
           "  -m, --max_len            Maximum length of the secret (default: 6)\n"
           "  -h, --hmac_alg           HMAC algorithm (default: sha256)\n"
           "  -d, --dictionary_file    Dictionary file containing potential secrets\n", cmd);
}

int load_dictionary(const char *file_path) {
    FILE *file = fopen(file_path, "r");
    if (!file) {
        printf("Could not open dictionary file: %s\n", file_path);
        return 0;
    }

    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    while ((read = getline(&line, &len, file)) != -1) {
        line[strcspn(line, "\n")] = '\0';  // Remove newline character
        g_dict = realloc(g_dict, (g_dict_size + 1) * sizeof(char *));
        g_dict[g_dict_size] = strdup(line);
        g_dict_size++;
    }

    fclose(file);
    free(line);
    return 1;
}

bool brute_dictionary(struct s_thread_data *data) {
    for (size_t i = 0; i < g_dict_size; i++) {
        if (check(data, g_dict[i], strlen(g_dict[i]))) {
            g_found_secret = strdup(g_dict[i]);
            return true;
        }
    }
    return false;
}

int main(int argc, char **argv) {
    const EVP_MD *evp_md;
    size_t max_len = 6;
    const char *default_hmac_alg = "sha256";
    g_alphabet = "eariotnslcudpmhgbfywkvxzjqEARIOTNSLCUDPMHGBFYWKVXZJQ0123456789";
    char *jwt = NULL;
    char *dictionary_file = NULL;

    // Parse command line options
    int opt;
    while ((opt = getopt(argc, argv, "t:a:m:h:d:")) != -1) {
        switch (opt) {
            case 't':
                jwt = optarg;
                break;
            case 'a':
                g_alphabet = optarg;
                break;
            case 'm':
                max_len = atoi(optarg);
                if (max_len <= 0) {
                    printf("Invalid max_len value %s, must be greater than 0, defaults to %zd\n", optarg, max_len);
                    max_len = 6; // Reset to default
                }
                break;
            case 'h':
                evp_md = EVP_get_digestbyname(optarg);
                if (evp_md == NULL) {
                    printf("Unknown message digest %s, will use default %s\n", optarg, default_hmac_alg);
                    evp_md = EVP_get_digestbyname(default_hmac_alg);
                }
                break;
            case 'd':
                dictionary_file = optarg;
                break;
            default:
                usage(argv[0]);
                return 1;
        }
    }

    if (jwt == NULL) {
        usage(argv[0]);
        return 1;
    }

    if (evp_md == NULL) {
        evp_md = EVP_get_digestbyname(default_hmac_alg);
        if (evp_md == NULL) {
            printf("Cannot initialize the default message digest %s, aborting\n", default_hmac_alg);
            return 1;
        }
    }

    g_alphabet_len = strlen(g_alphabet);
    g_header_b64 = strtok(jwt, ".");
    g_payload_b64 = strtok(NULL, ".");
    g_signature_b64 = strtok(NULL, ".");
    g_header_b64_len = strlen(g_header_b64);
    g_payload_b64_len = strlen(g_payload_b64);
    g_signature_b64_len = strlen(g_signature_b64);

    g_to_encrypt_len = g_header_b64_len + 1 + g_payload_b64_len;
    g_to_encrypt = (unsigned char *) malloc(g_to_encrypt_len + 1);
    sprintf((char *) g_to_encrypt, "%s.%s", g_header_b64, g_payload_b64);

    g_signature_len = Base64decode_len((const char *) g_signature_b64);
    g_signature = malloc(g_signature_len);
    g_signature_len = Base64decode((char *) g_signature, (const char *) g_signature_b64);

    struct s_thread_data *pointers_data[g_alphabet_len];
    pthread_t *tid = malloc(g_alphabet_len * sizeof(pthread_t));

    if (dictionary_file != NULL) {
        // Use dictionary mode
        if (!load_dictionary(dictionary_file)) {
            printf("Failed to load dictionary. Exiting.\n");
            return 1;
        }
        struct s_thread_data data;
        init_thread_data(&data, 0, max_len, evp_md);
        if (!brute_dictionary(&data)) {
            printf("No solution found using dictionary :-(\n");
        } else {
            printf("Secret is \"%s\" (from dictionary)\n", g_found_secret);
        }
        destroy_thread_data(&data);
    } else {
        // Use alphabet mode
        for (size_t i = 0; i < g_alphabet_len; i++) {
            pointers_data[i] = malloc(sizeof(struct s_thread_data));
            init_thread_data(pointers_data[i], g_alphabet[i], max_len, evp_md);
            pthread_create(&tid[i], NULL, (void *(*)(void *)) brute_sequential, pointers_data[i]);
        }

        for (size_t i = 0; i < g_alphabet_len; i++)
            pthread_join(tid[i], NULL);

        if (g_found_secret == NULL)
            printf("No solution found using alphabet :-(\n");
        else
            printf("Secret is \"%s\" (from alphabet)\n", g_found_secret);
    }

    free(g_found_secret);
    free(tid);
    for (size_t i = 0; i < g_dict_size; i++) {
        free(g_dict[i]);
    }
    free(g_dict);
    return 0;
}
