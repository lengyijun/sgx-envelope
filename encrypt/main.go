package main

// #cgo CFLAGS: -I/opt/intel/sgxsdk/include/
// #cgo LDFLAGS: ${SRCDIR}/libencrypt.a ${SRCDIR}/../sgx-sample/app/libapp.a /opt/openssl/1.1.0j/lib/libcrypto.so /opt/intel/sgxsdk/lib64/libsgx_urts.so
// #include "encrypt.h"
// #include "../sgx-sample/app/app.h"
import "C"
import "log"

const input="Hello world ";

func main(){
  str:=encrypt(input)
  decrypt(str)
}

func encrypt(cs string) string {
  c_char := C.CString(cs)
  var size C.int
  ptr,err:=C.encrypt(c_char,(C.int)(len(cs)),&size);
  if err!=nil{
    log.Fatalln("error")
  }
  str := C.GoStringN(ptr,size)
  // str := C.GoString(ptr)
  // str := C.GoBytes(ptr,size)
  log.Printf("%x\n",str)
  log.Printf("%d\n",size)
  return str
}

func decrypt(cs string){
  // log.Printf("decrypt size %d\n",len(cs))
  c_char := C.CString(cs)
  C.decrypt(c_char,(C.int)(len(cs)))
}
