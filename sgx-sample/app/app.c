/*
 * Copyright (C) 2019 Intel Corporation
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdio.h>
#include <getopt.h>

#include <openssl/evp.h>

#include "app.h"


static struct option long_options[] = {
    {"keygen", no_argument, 0, 0},
    {"decrypt", no_argument, 0, 0},
    {"enclave-path", required_argument, 0, 0},
    {"statefile", required_argument, 0, 0},
    {"encrypted-aes-key", required_argument, 0, 0},
    {"public-key", required_argument, 0, 0},
    {0, 0, 0, 0}};


void decrypt(char * encryptedString, int length)
{
    bool opt_decrypt = true;
    const char *opt_enclave_path = "/home/fpc/raft/sgx-sample/enclave/enclave.signed.so";
    const char *opt_statefile ="sealeddata.bin";
    const char *opt_input_file = NULL; //useless


    OpenSSL_add_all_algorithms(); /* Init OpenSSL lib */

    bool success_status = create_enclave(opt_enclave_path) &&
                          enclave_get_buffer_sizes() &&
                          allocate_buffers() &&
                          (opt_decrypt? load_enclave_state(opt_statefile) : true) &&
                          read_parameter_into_memory(encryptedString,length) &&
                          (opt_decrypt ? load_aes_and_input_file(opt_input_file):true) &&
                          (opt_decrypt ? enclave_decrypt_data() : true) &&
                          save_enclave_state(opt_statefile);

    if (sgx_lasterr != SGX_SUCCESS)
    {
        fprintf(stderr, "[GatewayApp]: ERROR: %s\n", decode_sgx_status(sgx_lasterr));
    }

    destroy_enclave();
    cleanup_buffers();

}

bool read_parameter_into_memory(char * encryptedString, int length){
  printf("[GatewayApp]: read_parameter_into_memory \n");
  toge_buffer_size=length;
  toge_buffer=calloc(toge_buffer_size,1);
  memcpy(toge_buffer,encryptedString,toge_buffer_size);

  // swap endian
  // char* p = (char*)toge_buffer;
  // for(int i=0;i<toge_buffer_size/2;i++){
    // char t=p[2*i];
    // p[2*i]=p[2*i+1];
    // p[2*i+1]=t;
  // }
  
  // ocall_print_hex(toge_buffer,toge_buffer_size);
  // printf("\n");

  return true;
}
