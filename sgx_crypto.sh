#!/bin/sh
set -e

#gcc -o encrypt encrypt.c -lcrypto
#计算节点 
cd sgx-sample
test -d demo_sgx || mkdir demo_sgx
cd demo_sgx
rm -f *
../app/app --keygen --enclave-path `pwd`/../enclave/enclave.signed.so --statefile sealeddata.bin --public-key pub.pem

#客户端
cd ../../encrypt
cp ../sgx-sample/demo_sgx/pub.pem pub.pem
./encrypt --keygen --public-key pub.pem --aes-key aes.bin --encrypted-aes-key e_aes.bin --ciphertext cipher.txt ./Sensor_Data
cp toge ../sgx-sample/demo_sgx/

#计算节点 
cd ../sgx-sample/demo_sgx
../app/app --decrypt --enclave-path `pwd`/../enclave/enclave.signed.so --statefile sealeddata.bin --encrypted-aes-key e_aes.bin toge
#../app/app --decrypt --enclave-path `pwd`/../enclave/enclave.signed.so --statefile sealeddata.bin --encrypted-aes-key e_aes.bin cipher.txt
cd ../..
