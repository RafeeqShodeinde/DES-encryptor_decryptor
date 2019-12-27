//Project Done by Rafeeq Shodeinde
//CS5650 Computer Security
//Dated on 06/10/2019

#include <iostream>
#include <cstring>
#include <fstream>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>


using namespace std;

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

/********************* Read private key into RSA buffer ************************************/

RSA *createPrivateRSA(const char *keyFilename)
{
    FILE *fp = fopen(keyFilename, "r");
    if(fp == NULL)
    {
        printf("cant open file");
        return NULL;
    }

    RSA *rsa = RSA_new();
    rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);

    fclose(fp);
    return rsa;
}

/******************* ENCRYPTION FUNCTION ******************************************/

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    //Initializes the context
    if(!(ctx = EVP_CIPHER_CTX_new())) { handleErrors(); }

    // INITIALIZE ENCRYPTION
    if (1 != EVP_EncryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv)) { handleErrors(); }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) { handleErrors(); }
    
    ciphertext_len = len;
    
    //FINALISE ENCRYPTION PROCESS
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) { handleErrors(); }
    ciphertext_len += len;

    EVP_CIPHER_CTX_cleanup(ctx);
    return ciphertext_len;
}

/********************* BASE64 ENCODE *********************************************/

void Base64Encode( const unsigned char* buffer, size_t length, char** base64Text)
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    *base64Text=(*bufferPtr).data;
}

/******************** Signing function *************************************************************/
bool RSASign( RSA* rsa, const unsigned char* Msg, size_t MsgLen, unsigned char** EncMsg, size_t* MsgLenEnc) 
{
    EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
    EVP_PKEY* priKey  = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(priKey, rsa);
    
    if (EVP_DigestSignInit(m_RSASignCtx,NULL, EVP_sha256(), NULL,priKey)<=0) { return false; }

    if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) { return false; }
    
    if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <=0) { return false; }
    
    *EncMsg = (unsigned char*)malloc(*MsgLenEnc);
    
    if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) { return false; }
    
    EVP_MD_CTX_cleanup(m_RSASignCtx);
    return true;

    free(priKey);
}

/******************* Signing process ************************************************************/
char* signing(const char *privateKey, unsigned char *cipherText) 
{
    RSA* privateRSA = createPrivateRSA(privateKey);
    unsigned char* encMessage;
    char* base64Text;
    size_t encMessageLength;
    
    RSASign(privateRSA, cipherText, sizeof(cipherText), &encMessage, &encMessageLength);
    Base64Encode(encMessage, encMessageLength, &base64Text);
    OPENSSL_free(encMessage);

    return base64Text;
}

/******************************************** MAIN ***********************************************/

int main()
{
    cout << "Enter decrypted session Key: ";
    string sessKey;
    cin >> sessKey;
    
    cout << "Enter plain text: ";
    string plaintext;
    cin >> plaintext;

    cout << "Enter Private Key: ";
    string privateKey;
    cin>> privateKey;

    unsigned char *ciphertxt = (unsigned char *) malloc(4098);
    unsigned char IV[20]; 

    ifstream fin("IV.txt");

    if (!fin)
    {
        if(!RAND_bytes(IV, sizeof(IV))){}

	FILE *ivFile = fopen("IV.txt", "w");
        fwrite(IV, sizeof(IV), sizeof(IV), ivFile);
        fclose(ivFile);
    }

    /********* READ base64 sessionkey for encryption *************/
        
    FILE *decSess = fopen(sessKey.c_str(),"r");
    fseek(decSess, 0, SEEK_END);
    int decSessKeyLen = ftell(decSess);
    fseek(decSess, 0, SEEK_SET);

    unsigned char *sessKeyBuffer = (unsigned char *) malloc(decSessKeyLen); //Buffer that holds base64 decrypted session key

    while(!feof(decSess)) {fread(sessKeyBuffer, sizeof(sessKeyBuffer), decSessKeyLen, decSess);}
    fclose(decSess); 
    
    /********** READ plainTEXT FILE INTO A BUFFER *****************/
    
    FILE *ptxt = fopen(plaintext.c_str(),"r");
    fseek(ptxt, 0, SEEK_END);
    int plainLen = ftell(ptxt);
    fseek(ptxt, 0, SEEK_SET);

    unsigned char *plainBuffer = (unsigned char *) malloc(plainLen); //Buffer that holds plaintext

    while(!feof(ptxt)) { fread(plainBuffer, sizeof(plainBuffer), plainLen, ptxt); }
    fclose(ptxt);

    /**************** Encryption process **********************************/
    
    int ciphertext_len = encrypt(plainBuffer, plainLen, sessKeyBuffer, IV, ciphertxt);

    /********** Write ciphertext into a text file ***********************/
        
    FILE *cipherTxt = fopen("cipher.txt", "w");
    if(cipherTxt == NULL)
    {
        printf("Error loading cipher txt file \n");
        exit(1);
    }

    char* cipherbase64;
    Base64Encode(ciphertxt, ciphertext_len, &cipherbase64);

    fwrite(cipherbase64, sizeof(cipherbase64), ciphertext_len, cipherTxt);
    fclose(cipherTxt);

    /********** Signing the ciphertext then converting to base64 format ******************/
    
    char *signedOutput = signing(privateKey.c_str(), ciphertxt);

    FILE *cipherBase64 = fopen("signCipherBase64.txt", "w");

    if(cipherBase64 == NULL)
    {
        printf("Error loading non base64 cipher txt file \n");
        exit(1);
    }

    fwrite(signedOutput, sizeof(signedOutput), ciphertext_len, cipherBase64);
    fclose(cipherBase64);

    OPENSSL_free(ciphertxt);
    OPENSSL_free(sessKeyBuffer);
    OPENSSL_free(plainBuffer);
    OPENSSL_free(signedOutput);
}
