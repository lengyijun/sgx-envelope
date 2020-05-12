# sgx-envelope
把数字信封传给sgx

pub.pem: 公钥

sealeddata.bin: 加密的私钥

toge: 数字信封。前256位是加密的对称密钥。后面长度不定的是对称密钥加密的数据


