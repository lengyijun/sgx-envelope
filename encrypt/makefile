#
# Copyright (C) 2019 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

include ../sgx-sample/common/common.mk
include ../sgx-sample/common/rules.mk

SGX_EDGER8R_FLAGS += --untrusted-dir ../interface
CFLAGS += $(SGX_HOST_CFLAGS) -std=c99
CXXFLAGS += $(SGX_HOST_CXXFLAGS)
#CPPFLAGS += -I/opt/openssl/1.1.0j/include 
CPPFLAGS += $(SGX_HOST_CPPFLAGS) -g
LDFLAGS += $(SGX_HOST_LDFLAGS) 
# Add to LDFLAGS if enclave_stub_u is a shared library: -Wl,-rpath,../interface -Wl,-rpath,interface
# LDLIBS += -L ../interface -lenclave_stub_u $(SGX_HOST_LDLIBS) -lcrypto -ldl
LDLIBS += -lcrypto -ldl

.PHONY: all clean

all: libencrypt.a
	rm -f encrypt
	go build -o encrypt

clean:
	rm -f aes.bin cipher.txt e_aes.bin encrypt encrypt.o toge libencrypt.a 

libencrypt.a: encrypt.o ocall_print_string.o
	ar rs $@ $^
