#ifndef _ENCRYPT_H
#define _ENCRYPT_H

#include <sys/types.h>
#include <stdbool.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

void *input_buffer;
size_t input_buffer_size;
void *aes_buffer;
size_t aes_buffer_size;
void *ctr_buffer;
size_t ctr_buffer_size;
void *encrypted_aes_buffer;
size_t encrypted_aes_buffer_size;
void *public_key_buffer;
size_t public_key_buffer_size;
void *encrypt_buffer;
size_t encrypt_buffer_size;
void *toge_buffer;
size_t toge_buffer_size;


EVP_PKEY* open_public_key(const char *keyfile);
bool generate_aes_key();
bool rsa_encrypt_data(void* rsa_key, unsigned char* pout_data, size_t* pout_len, const unsigned char* pin_data, const size_t pin_len);
bool aes_encrypt_data();
bool save_ciphertext(const char *const ciphertext_file);
bool save_aes_key(const char *const aes_file);
bool save_encrypt_aes_key(const char *const encrypted_aes_file);
bool save_together();
bool read_file_into_memory(const char *const filename, void **buffer, size_t *buffer_size);
void ocall_print_string(const char *str);
void ocall_print_hex(unsigned char *p,size_t size);
char * encrypt(char * input, int length,int * size);

#endif
