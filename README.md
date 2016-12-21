# Encrypt-Decrypt-with-OpenSSL-RSA

## What is OpenSSL ?
OpenSSL is opensource library that provide secure communication over networks using TLS (Transfer Secure Layer) and SSL (Secure Socket Layer). 
It supports many cryptographic algorithm AES, DSA, RSA, SHA1, SHA2, MD5.. More information about [OpenSSL] (https://en.wikipedia.org/wiki/OpenSSL) 

## What is RSA ? 
RSA is algorithm using for encrypting and decrypting data. 
It is in the class of asymmetric cryptographic algorithm (public key cryptography). 
Asymmetric cryptographic algorithm has two different keys. 
They are *public key and private key*. Public key is given everyone. 
Private key is secret. 
Data is encrypted by public key then decrypted by private key.
More information about [RSA Algorithm] (https://simple.wikipedia.org/wiki/RSA_(algorithm)) 

## Steps of RSA Algorithm
**1 -** Define two different prime numbers. ( p and q) <br />
**2 -** Calculate modulus for private key and public key. n = p * q <br />
**3 -** Caluclate totient. Q(n) = (p -1) * (q -1) <br />
**4 -** Define public key exponent (e). e must be in 1 < e < Q(n). e and Q(n) are relatively prime. <br />
**5 -** Define private key exponent (d). It must be secret. d*e = 1 + kQ(n). d must be in 1 < d < Q(n) <br />

### Encrypt Message

c = m^e mod (n)

### Decrypt Message

m = c^d mod (n)

### Sample

**1 -** p = 3 and q = 11 <br />
**2 -** modulus n = 3 * 11 = 33 <br />
**3 -** totient Q(n) = (3 - 1) * (11 - 1) = 20 <br />
**4 -** 1 < e < 20 and e = 7 <br />
**5 -** de mod Q(n) = 1 and 7d mod 20 = 1, d = 3 <br />
<br />
Message can be 4. m = 4 <br />
**Encrypt message:** c = 4^7 mod (33) = 16384 mod (33) and c = 16. Encrypted message is 16 <br />
**Decrypt message:** m = 16^3 mod (33) = 4096 mod (33) and m = 4. Decrypted message is 4 <br />

