//Project done by Rafeeq Shodeinde
//CS5650 COmputer Security
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

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

/******************* Read public key into RSA buffer ****************************************/

RSA *createPublicRSA(const char *keyFilename)
{
    FILE *fp = fopen(keyFilename, "r");
    if(fp == NULL) { printf("cant open file"); return NULL; }

    RSA *rsa = RSA_new();
    rsa = PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);

    fclose(fp);
    return rsa;
}

/*************************** Decryption method **********************************************/

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) { handleErrors(); }

    if(1 != EVP_DecryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv)) { handleErrors(); }

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) { handleErrors(); }
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) { handleErrors(); }
    plaintext_len += len;

    EVP_CIPHER_CTX_cleanup(ctx);

    return plaintext_len;
}

/*************** Verify Signature Method ********************************************/

bool RSAVerifySignature( RSA* rsa, unsigned char* MsgHash, size_t MsgHashLen, unsigned char* Msg, size_t MsgLen, bool* Authentic)
{
    *Authentic = false;
    EVP_PKEY* pubKey  = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pubKey, rsa);
    EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

    if (EVP_DigestVerifyInit(m_RSAVerifyCtx,NULL, EVP_sha256(),NULL,pubKey)<=0) {return false;}
    
    if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {return false;}
    
    int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
    
    if (AuthStatus==1){
        *Authentic = true;
        EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
        return true;} 
    
    else if(AuthStatus==0){
        *Authentic = false;
        EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
        return true;} 
    
    else{
        *Authentic = false;
        EVP_MD_CTX_cleanup(m_RSAVerifyCtx);
        return false;}
}

/*****************************************************************************************/

size_t calcDecodeLength(const char* b64input)
{
    size_t len = strlen(b64input), padding = 0;

    if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
    {padding = 2;}
      
    else if (b64input[len-1] == '=') //last char is =
    {padding = 1;}

    return (len*3)/4 - padding;
}

/******************** Base64 decoding ***************************************************/

void Base64Decode(const char* b64message, unsigned char** buffer, size_t* length)
{
    BIO *bio, *b64;

    int decodeLen = calcDecodeLength(b64message);
    *buffer = (unsigned char*)malloc(decodeLen + 1);
    (*buffer)[decodeLen] = '\0';

    bio = BIO_new_mem_buf(b64message, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    *length = BIO_read(bio, *buffer, strlen(b64message));
    BIO_free_all(bio);
}

/*************************** verifying process ***************************************/

bool verifying( const char *publicKey, unsigned char *cipherText, char *signatureBase64)
{
    RSA* publicRSA = createPublicRSA(publicKey);
    unsigned char* encMessage;
    size_t encMessageLength;
    bool authentic;
    Base64Decode(signatureBase64, &encMessage, &encMessageLength);
    bool result = RSAVerifySignature(publicRSA, encMessage, encMessageLength, cipherText, sizeof(cipherText), &authentic);
    OPENSSL_free(publicRSA);
    OPENSSL_free(encMessage);
    return result &authentic;
}

/************************ MAIN ************************************/

int main()
{   
    cout << "Enter decrypted session Key: ";
    string sessKey;
    cin >> sessKey;

    cout << "Enter Public Key: ";
    string publicKey;
    cin >> publicKey;

    cout << "Enter signed cipher text: ";
    string signedCipher;
    cin >> signedCipher;

    cout << "enter CIpher text: ";
    string ciphertext;
    cin >> ciphertext;

    cout <<  "enter IV file: ";
    string IVfile;
    cin >> IVfile;

    /********* READ base64 sessionkey for decryption *************/

    FILE *decSess = fopen(sessKey.c_str(),"r");
    fseek(decSess, 0, SEEK_END);
    int decSessKeyLen = ftell(decSess);
    fseek(decSess, 0, SEEK_SET);

    unsigned char *sessKeyBuffer = (unsigned char *) malloc(decSessKeyLen); //Buffer that holds base64 decrypted session key

    while(!feof(decSess)) { fread(sessKeyBuffer, sizeof(sessKeyBuffer), decSessKeyLen, decSess); }
    fclose(decSess);


    /********* READ cipherTEXT FILE INTO A BUFFER *****************/

    FILE *ctxt = fopen(ciphertext.c_str(),"r");
    fseek(ctxt, 0, SEEK_END);
    int cipherTextLen = ftell(ctxt);
    fseek(ctxt, 0, SEEK_SET);

    char *cipherTextBuffer = (char *) malloc(cipherTextLen); //Buffer that holds ciphertext

    while(!feof(ctxt)) { fread(cipherTextBuffer, sizeof(cipherTextBuffer), cipherTextLen, ctxt); }
    fclose(ctxt);


    /********** Converts Ciphertext from base64 *****************/

    unsigned char* nonBase64Cipher;
    size_t nonBase64CipherLen;
    Base64Decode(cipherTextBuffer, &nonBase64Cipher, &nonBase64CipherLen);

    /************** READ IV text file ***************************/

    FILE *ivFile = fopen(IVfile.c_str(), "r");
    fseek(ivFile, 0, SEEK_END);
    int ivLen = ftell(ivFile);
    fseek(ivFile, 0, SEEK_SET);

    unsigned char *ivBuffer = (unsigned char *) malloc(ivLen); //Buffer that holds IV

    while(!feof(ivFile)) { fread(ivBuffer, sizeof(ivBuffer), ivLen, ivFile); }
    fclose(ivFile);

    /*********** VERIFICATION OF SIGNATURE ****************/

    /******** READ signed base64 cipher *****************/
    
    FILE *sign = fopen(signedCipher.c_str(),"r");
    fseek(sign, 0, SEEK_END);
    int signedLen = ftell(sign);
    fseek(sign, 0, SEEK_SET);

    char *signature = (char *) malloc(signedLen);

    while(!feof(sign)) { fread(signature, sizeof(signature), signedLen, sign); }
    fclose(sign);

    /************* Verification Process ********************/

    bool authentic = verifying(publicKey.c_str(), nonBase64Cipher, signature);

    if(authentic)
    {
        cout << "Authentication done\n\n";
    }
    else{
        cout << "NOT AUTHENTICATED ERROR!!\n";
    }

    OPENSSL_free(signature);


    /****************** DECRYPTING CIPHERTEXT ********************/

    unsigned char *decryptedText = (unsigned char *) malloc(4098);

    /***************** Decryption Process ************************/
      
    int decryptedtext_len = decrypt( nonBase64Cipher, nonBase64CipherLen, sessKeyBuffer, ivBuffer, decryptedText);

    decryptedText[decryptedtext_len] = '\0';

    /******** Print PlainText to terminal **************/

    printf("Decrypted text is:\n\n");
    printf("%s\n", decryptedText);


    OPENSSL_free(sessKeyBuffer);
    OPENSSL_free(ivBuffer);
    OPENSSL_free(nonBase64Cipher);
    OPENSSL_free(cipherTextBuffer);
    OPENSSL_free(decryptedText);

}
