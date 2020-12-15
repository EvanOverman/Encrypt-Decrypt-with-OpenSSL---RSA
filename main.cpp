#include <iostream>
#include <fstream>
#include <cstring>
#include <string>

#include "openssl/rsa.h" // <openssl.rsa.h>
#include "openssl/pem.h" // <openssl/pem.h>
#include "openssl/err.h" // <openssl/err.h>
// #include "rsa.hpp"
#include "openssl_rsa.h"

int main (int argc, const char *argv[]) 
{
    std::clog << "OpenSSL_RSA has been started.\n";
    
    RSA *private_key;
    RSA *public_key;

    std::string private_key_pem = "private_key";
    std::string public_key_pem = "public_key";

    bool do_decrypt = false;
    bool do_encrypt = false;

    std::string encrypted_file = "encrypted_file.txt";
    std::string outfile = "decrypted_file.txt";

    for (int count = 0; count < argc; count++)
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

    std::string file = std::string(argv[argc - 1]);
    std::string line;
    std::string message;

    std::fstream infile(file, std::fstream::in);

    while (getline(infile, line))
    {
        message += line + "\n";
    }

    // char message[KEY_LENGTH / 8] = "Batuhan AVLAYAN - OpenSSL_RSA demo";
    char *encrypt = NULL;
    char *decrypt = NULL;    

    std::clog << KEY_LENGTH << "\n";
    std::clog << PUBLIC_EXPONENT << "\n";
    
    RSA *keypair = RSA_generate_key(KEY_LENGTH, PUBLIC_EXPONENT, NULL, NULL);
    std::clog << "Generate key has been created.\n";

    private_key = create_RSA(keypair, PRIVATE_KEY_PEM, private_key_pem);
    std::clog << "Private key pem file has been created.\n";

    public_key  = create_RSA(keypair, PUBLIC_KEY_PEM, public_key_pem);      
    std::clog << "Public key pem file has been created.\n";

    encrypt = (char*)malloc(RSA_size(public_key));
    int encrypt_length = public_encrypt(strlen(message.c_str()) + 1, (unsigned char*)message.c_str(), (unsigned char*)encrypt, public_key, RSA_PKCS1_OAEP_PADDING);

    if (encrypt_length == -1) 
    {
        std::cerr << "An error occurred in public_encrypt() method\n";
        return 1;
    }

    std::clog << "Data has been encrypted.\n";

    create_encrypted_file(encrypt, public_key, outfile);
    std::clog << "Encrypted file has been created.\n";

    decrypt = (char *)malloc(encrypt_length);
    int decrypt_length = private_decrypt(encrypt_length, (unsigned char*)encrypt, (unsigned char*)decrypt, private_key, RSA_PKCS1_OAEP_PADDING);

    if (decrypt_length == -1) 
    {
        std::cerr << "An error occurred in private_decrypt() method\n";
        return 1;
    }

    std::clog << "Data has been decrypted.\n";

    FILE *decrypted_file = fopen(outfile.c_str(), "w");
    fwrite(decrypt, sizeof(*decrypt), decrypt_length - 1, decrypted_file);
    fclose(decrypted_file);
    std::clog << "Decrypted file has been created.\n";
    
    RSA_free(keypair);
    free(private_key);
    free(public_key);
    free(encrypt);
    free(decrypt);
    std::clog << "OpenSSL_RSA has been finished.\n";

    return 0;

}
