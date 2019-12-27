//Project Done by Rafeeq Shodeinde
//CS5650 Computer Security
//Dated on 06/10/2019


#include <iostream>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/buffer.h>

#include <cstring>

using namespace std;

/******** Read Third party public key ***********************/

RSA *createRSA(const char *keyFilename)
{
    FILE *fp = fopen(keyFilename, "r");
    if(fp == NULL)
    {
        printf("cant open file");
	return NULL;
    }

    RSA *rsa = RSA_new();
    rsa = PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);
    
    fclose(fp);
    return rsa;
}

/********************** Session Key decrypt function *****************************************/

int public_decrypt(unsigned char * enc_data, int data_len, const char * key, unsigned char * decrypted)
{
    RSA *rsa = createRSA(key);
    int padding = RSA_NO_PADDING;
    int result = RSA_public_decrypt(data_len, enc_data, decrypted, rsa, padding);
    OPENSSL_free(rsa);
    return result;
}

/*********** Base64 Encoding *********************/

char *base64(unsigned char *input, int length)
{
    BIO *bmem, *b64;
    BUF_MEM *bptr;
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, input, length);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bptr);

    char *buff = (char *)malloc(bptr->length);
    memcpy(buff, bptr->data, bptr->length-1);
    buff[bptr->length-1] = 0;
 
    BIO_free_all(b64);

    return buff;
}

/************************** MAIN ********************************/

int main() {


    cout << "Enter encrypted session key: ";
    string sessKey;
    cin >> sessKey;
    
    cout << "Enter third party public key: ";
    string t_pubKey;
    cin >> t_pubKey;

    unsigned char *decryptSessBuffer  = (unsigned char *) malloc(4098); //Buffer that holds decrypted session key

    /***********  Reading in neccessary files. *******************/
    
    /***********  Session Key into *sessBuffer *******************/
        
    FILE *sess = fopen(sessKey.c_str(),"r");
    fseek(sess, 0, SEEK_END);
    int encSessKeyLen = ftell(sess);
    fseek(sess, 0, SEEK_SET);
    
    unsigned char *sessBuffer = (unsigned char *) malloc(encSessKeyLen); //Buffer that holds encrypted session key

    while(!feof(sess)) { fread(sessBuffer, sizeof(sessBuffer), encSessKeyLen, sess); }
    fclose(sess);
   
    
    /********* DECRYPTING ENCRYPTED SESSION KEY INTO *decryptSessBuffer ****************/
        
    int decrypted_length = public_decrypt(sessBuffer, encSessKeyLen, t_pubKey.c_str(), decryptSessBuffer);
    
    if(decrypted_length == -1)
    {
        printf("decrypt failed");
        exit(0);
    }
    
    
    /******************* Writing dec Session key in deSessKey.txt file. ******************/
    
    FILE *decTxt = fopen("decSessKey.txt", "w");
    
    if(decTxt == NULL)
    {
        printf("Error loading dec session key txt file \n");
        exit(1);
    }

    fwrite(decryptSessBuffer, sizeof(decryptSessBuffer), decrypted_length, decTxt);
    fclose(decTxt);

    /************ TURNING DECRYPTED SESSION KEY TXT FILE TO BASE64 ENCODING **************/
    
    FILE *base = fopen("decSessKey.txt","r");
    fseek(base, 0, SEEK_END);
    int decSessLen = ftell(base);
    fseek(base, 0, SEEK_SET);

    unsigned char *base64buffer = (unsigned char *) malloc(decSessLen);
    
    while(!feof(base)) { fread(base64buffer, sizeof(base64buffer), decSessLen, base); }
    fclose(base);

    char *cipherOutput = base64(base64buffer, sizeof(base64buffer));

    FILE *decBase64 = fopen("decSessBase64.txt", "w");

    if(decBase64 == NULL)
    {
        printf("Error loading dec session key txt file \n");
        exit(1);
    }

    fwrite(cipherOutput, sizeof(cipherOutput), decrypted_length, decBase64);
    fclose(decBase64);

    OPENSSL_free(sessBuffer);
    OPENSSL_free(decryptSessBuffer);
    OPENSSL_free(base64buffer);
    OPENSSL_free(cipherOutput);

    system("rm decSessKey.txt");
}
