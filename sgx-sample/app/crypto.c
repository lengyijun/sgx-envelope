#include <stdio.h>
#include <stdlib.h>

#include <enclave_u.h> /* For sgx_enclave_id_t */

#include "app.h"

bool load_input_file(const char *const input_file)
{
    printf("[GatewayApp]: Loading input file\n");

    return read_file_into_memory(input_file, &input_buffer, &input_buffer_size);
}

bool load_ase_file(const char *const aes_key_file)
{
    printf("[GatewayApp]: Loading input file\n");

    return read_file_into_memory(aes_key_file, &encrypted_aes_buffer, &encrypted_aes_buffer_size);
}

bool load_aes_and_input_file(const char *const input_file){
    printf("[GatewayApp]: Loading aes and input file\n");
    printf("toge_buffer_size:%zu\n",toge_buffer_size);

    encrypted_aes_buffer_size=256;
    input_buffer_size=toge_buffer_size-encrypted_aes_buffer_size;

    printf("encrypted_aes_buffer_size:%zu\n",encrypted_aes_buffer_size);
    printf("input_buffer_size:%zu\n",input_buffer_size);


    encrypted_aes_buffer=calloc(encrypted_aes_buffer_size,1);
    input_buffer=calloc(input_buffer_size,1);

    memcpy(encrypted_aes_buffer,toge_buffer,encrypted_aes_buffer_size);
    memcpy(input_buffer,toge_buffer+encrypted_aes_buffer_size,input_buffer_size);

  // ocall_print_hex(encrypted_aes_buffer,encrypted_aes_buffer_size);
  // printf("\n");
  // ocall_print_hex(input_buffer,input_buffer_size);
  // printf("\n");

    free(toge_buffer);
    toge_buffer=NULL;


    return true;
}


bool enclave_decrypt_data()
{
    sgx_status_t ecall_retval = SGX_ERROR_UNEXPECTED;

    printf("[GatewayApp]: Calling enclave to generate key material\n");
    sgx_lasterr = ecall_unseal_and_decrypt(enclave_id,
                                        &ecall_retval,
                                        (uint8_t *)input_buffer,
                                        (uint32_t)input_buffer_size,
                                        (uint8_t *)encrypted_aes_buffer,
                                        (uint32_t)encrypted_aes_buffer_size,
                                        (char *)sealed_data_buffer,
                                        sealed_data_buffer_size);
    if (sgx_lasterr == SGX_SUCCESS &&
        (ecall_retval != 0))
    {
        fprintf(stderr, "[GatewayApp]: ERROR: ecall_unseal_and_decrypt returned %d\n", ecall_retval);
        sgx_lasterr = SGX_ERROR_UNEXPECTED;
    }

    return (sgx_lasterr == SGX_SUCCESS);
}
