//
// rsa.hpp
// Functions: bavlayan
//

#ifndef RSA_ALGORITHM_H

#include "openssl/rsa.h" // <openssl.rsa.h>
#include "openssl/pem.h" // <openssl/pem.h>
#include "openssl/err.h" // <openssl/err.h>

#define RSA_ALGORITHM_H

#define KEY_LENGTH       2048
#define PUBLIC_EXPONENT  79     //Public exponent should be a prime number.
#define PUBLIC_KEY_PEM   1
#define PRIVATE_KEY_PEM  0


RSA *create_RSA(RSA *keypair, int pem_type, std::string file_name) 
{
    RSA   *rsa = NULL;
    FILE  *fp  = NULL;

    if(pem_type == PUBLIC_KEY_PEM) 
    {

        fp = fopen(file_name.c_str(), "w");
        PEM_write_RSAPublicKey(fp, keypair);
        fclose(fp);

        fp = fopen(file_name.c_str(), "rb");
        PEM_read_RSAPublicKey(fp, &rsa, NULL, NULL);
        fclose(fp);

    }

    else if(pem_type == PRIVATE_KEY_PEM) 
    {

        fp = fopen(file_name.c_str(), "w");
        PEM_write_RSAPrivateKey(fp, keypair, NULL, NULL, 0, NULL, NULL);
        fclose(fp);

        fp = fopen(file_name.c_str(), "rb");
        PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
        fclose(fp);

    }

    return rsa;
}

int public_encrypt(int flen, unsigned char *from, unsigned char *to, RSA* key, int padding) 
{
    int result = RSA_public_encrypt(flen, from, to, key, padding);
    return result;
}

int private_decrypt(int flen, unsigned char *from, unsigned char *to, RSA *key, int padding) 
{
    int result = RSA_private_decrypt(flen, from, to, key, padding);
    return result;
}

void create_encrypted_file(char *encrypted, RSA *key_pair) 
{
    FILE* encrypted_file = fopen("encrypted_file.bin", "w");
    fwrite(encrypted, sizeof(*encrypted), RSA_size(key_pair), encrypted_file);
    fclose(encrypted_file);
}

#endif