#!/usr/bin/bash

openssl genrsa -out rsa2048.pem 2048
openssl rsa -in rsa2048.pem -pubout -out rsa2048_pub.pem

# DER
openssl rsa -in rsa2048.pem -outform der -out rsa2048.der
openssl rsa -in rsa2048.pem -outform der -pubout -out rsa2048_pub.der
openssl rsa -in rsa2048.pem -outform der -RSAPublicKey_out -out rsa2048_pub_short.der

# PKCS#8
openssl pkcs8 -topk8 -in rsa2048.pem -nocrypt -out rsa2048_p8.pem
openssl pkcs8 -topk8 -in rsa2048.pem -nocrypt -outform der -out rsa2048_p8.pem

# Encrypted PEM
openssl rsa -in rsa2048.pem -passout pass:secret -aes128 -out rsa2048_aes128.pem
openssl rsa -in rsa2048.pem -passout pass:secret -aes192 -out rsa2048_aes192.pem
openssl rsa -in rsa2048.pem -passout pass:secret -aes256 -out rsa2048_aes256.pem
openssl rsa -in rsa2048.pem -passout pass:secret -des -out rsa2048_des.pem
openssl rsa -in rsa2048.pem -passout pass:secret -des3 -out rsa2048_des3.pem

# Encrypted PKCS#8
openssl pkcs8 -topk8 -in rsa2048.pem -passout pass:secret -v1 PBE-SHA1-3DES -out rsa2048_p8_pbe.pem
openssl pkcs8 -topk8 -in rsa2048.pem -passout pass:secret -v2 des3 -out rsa2048_p8_des3.pem
openssl pkcs8 -topk8 -in rsa2048.pem -passout pass:secret -v2 aes128 -out rsa2048_p8_aes128.pem
openssl pkcs8 -topk8 -in rsa2048.pem -passout pass:secret -v2 aes192 -out rsa2048_p8_aes192.pem
openssl pkcs8 -topk8 -in rsa2048.pem -passout pass:secret -v2 aes256 -v2prf hmacWithSHA512 -out rsa2048_p8_aes256.pem
openssl pkcs8 -topk8 -in rsa2048.pem -passout pass:secret -scrypt -out rsa2048_p8_scrypt.pem
openssl pkcs8 -topk8 -in rsa2048.pem -passout pass:secret -outform der -out rsa2048_p8.pem

# New style
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -pass pass:secret -aes-128-cbc -out rsa2048_2.pem

# RSA-PSS
openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -pass pass:secret -aes-128-cbc -out rsa2048_pss_1.pem
openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_pss_keygen_md:sha512 -pkeyopt rsa_pss_keygen_mgf1_md:sha384 -pkeyopt rsa_pss_keygen_saltlen:100 -pass pass:secret -aes-128-cbc -out rsa2048_pss_2.pem

# SSH
#ssh-keygen -e -m RFC4716 -f rsa2048_pub.pem > rsa2048_pub_ssh.txt
#ssh-keygen -i -m PKCS8 -f rsa2048_pub.pem > rsa2048_pub_ssh.txt

# X.509
