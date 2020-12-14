#include <iostream>
#include <string>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include "openssl_rsa.h"

int main (int argc, const char *argv[]) 
{
    LOG("OpenSSL_RSA has been started.");
    
    RSA *private_key;
    RSA *public_key;

    std::string private_key_pem = "private_key";
    std::string public_key_pem = "public_key";

    bool do_decrypt = false;
    bool do_encrypt = false;

    std::string encrypted_file = "encrypted_file.bin";
    std::string outfile = "decrypted_file.txt"

    for (count = 0; count < argc; count++)
    {
        if (std::string(argv[count]) == "/r") // Private Key
        {
            private_key_pem = std::string(argv[count + 1]);
            count++;
        }

        else if (std::string(argv[count]) == "/u") // Public Key
        {
            public_key_pem = std::string(argv[count + 1]);
            count++;
        }

        else if (std::string(argv[count]) == "/o") // Outfile name
        {
            outfile = std::string(argv[count + 1]);
            count++;
        }

        else if (std::string(argv[count]) == "/d") // Decrypt
        {
            do_decrypt = true;
        }
        
        else if (std::string(argv[count]) == "/e") // Encrypt
        {
            do_encrypt = true;
        }
        
    }

    char message[KEY_LENGTH / 8] = "Batuhan AVLAYAN - OpenSSL_RSA demo";
    char *encrypt = NULL;
    char *decrypt = NULL;

    

    LOG(KEY_LENGTH);
    LOG(PUBLIC_EXPONENT);
    
    RSA *keypair = RSA_generate_key(KEY_LENGTH, PUBLIC_EXPONENT, NULL, NULL);
    LOG("Generate key has been created.");

    private_key = create_RSA(keypair, PRIVATE_KEY_PEM, private_key_pem);
    LOG("Private key pem file has been created.");

    public_key  = create_RSA(keypair, PUBLIC_KEY_PEM, public_key_pem);
    LOG("Public key pem file has been created.");;

    encrypt = (char*)malloc(RSA_size(public_key));
    int encrypt_length = public_encrypt(strlen(message) + 1, (unsigned char*)message, (unsigned char*)encrypt, public_key, RSA_PKCS1_OAEP_PADDING);

    if (encrypt_length == -1) 
    {
        LOG("An error occurred in public_encrypt() method");
    }

    LOG("Data has been encrypted.");

    create_encrypted_file(encrypt, public_key);
    LOG("Encrypted file has been created.");

    decrypt = (char *)malloc(encrypt_length);
    int decrypt_length = private_decrypt(encrypt_length, (unsigned char*)encrypt, (unsigned char*)decrypt, private_key, RSA_PKCS1_OAEP_PADDING);

    if (decrypt_length == -1) 
    {
        LOG("An error occurred in private_decrypt() method");
    }

    LOG("Data has been decrypted.");

    FILE *decrypted_file = fopen("decrypted_file.txt", "w");
    fwrite(decrypt, sizeof(*decrypt), decrypt_length - 1, decrypted_file);
    fclose(decrypted_file);
    LOG("Decrypted file has been created.");
    
    RSA_free(keypair);
    free(private_key);
    free(public_key);
    free(encrypt);
    free(decrypt);
    LOG("OpenSSL_RSA has been finished.");

    return 0;
}
