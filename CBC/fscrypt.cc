#include "openssl/blowfish.h"
#include "fscrypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void* fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen)
{
    //Declaring the key and the IV.
    BF_KEY *key = (BF_KEY*) malloc(sizeof(BF_KEY));
    int keylength = strlen(keystr);
    char iv = '0';
    int blocks = (bufsize-1)/BLOCKSIZE;

    unsigned char plainTextTemp[blocks][BLOCKSIZE];
    unsigned char *cipherText = (unsigned char *) malloc((blocks*BLOCKSIZE)*sizeof(unsigned char));
    unsigned char plaint[BLOCKSIZE],ciphert[BLOCKSIZE];
    unsigned char plaintxt[bufsize];

    memcpy(plaintxt,(unsigned char *) plaintext,bufsize);
    

    //finding out the number of padding bits that are needed  if text is greater than the block isze.    
    int padding = 0;
    padding = (bufsize-1)%BLOCKSIZE;
    if(padding > 0)
    {
        blocks += 1;
    }

    //Setting up the KEY using the BF_set_key();
    BF_set_key(key, keylength,(unsigned char*)keystr);
    //printf("Key has been setup.\n");
    //printf("\nbufsize =%d padding = %d blocks = %d\n",bufsize, padding,blocks);

    //Initializing the 2d array and storing the plaintext in blocks.
    int i=0,j=0,len=0,length = 0;
    while(i<blocks)
    {
        for(j=0;len<bufsize-1;j++)
        {
            plainTextTemp[i][j] = plaintxt[len++];
        }
        i++;
    }
       
    //Adding extra padding bits to the 2d array till i

    i = padding;
    while(i >0 && i <=BLOCKSIZE-1)
    {
        plainTextTemp[blocks-1][i] = (BLOCKSIZE - padding - 1) + '0';
        i++;
    }

    /* As IV is 0. this is to the EOR 
     * of IV and cipher text for the first iteration will be 0.
     * So directly initializing ciphertext to 0.        
     */

    for(i=0;i<BLOCKSIZE;i++)
    {
        ciphert[i] = iv;
    }

    int k=0;
    
    while(k<blocks)
    {
        for(i=0;i<BLOCKSIZE;i++)
        {
            plaint[i] = ciphert[i]^plainTextTemp[k][i];
        }

        BF_ecb_encrypt((unsigned char*) plaint, (unsigned char*) ciphert, key, BF_ENCRYPT);

        for(i = 0; i < BLOCKSIZE; i++)
        { 
            cipherText[length++] = ciphert[i];
        }

        k++;
    }
    *resultlen = length;
    free(key);
    free(cipherText);

    return (void *)cipherText;

}// end of encrypt function.

void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen)
{
    
    int blocks = (bufsize)/BLOCKSIZE;
    char iv = '0';
    BF_KEY *key = (BF_KEY*) malloc(sizeof(BF_KEY));

    // Declare and initialize the cipher text.
    unsigned char cipherTxt[bufsize];
    memcpy(cipherTxt,(unsigned char *) ciphertext,bufsize);

    unsigned char cipherTextTemp[++blocks][BLOCKSIZE]; 
    unsigned char *plainText = (unsigned char *) malloc((blocks*BLOCKSIZE)*sizeof(unsigned char));
    unsigned char plaint[BLOCKSIZE],ciphert[BLOCKSIZE];
    unsigned char *plainTextTemp = (unsigned char*) malloc(sizeof(unsigned char));
    unsigned char *finalPlainText = (unsigned char*) malloc(sizeof(unsigned char));
   
    // Set up the Key using the BF_Set_key().
    BF_set_key(key, strlen(keystr),(unsigned char*)keystr);
    
    int i=0, j=0,tempi=0,k=0,flag = 0,length=0;
    
    //Setting up IV
    for(i=0;i<BLOCKSIZE;i++)
    { 
        cipherTextTemp[0][i] = iv;
    }

    for(i=1;i<blocks;i++)
    {
        for(j=0;j<BLOCKSIZE;j++)
        {
            cipherTextTemp[i][j] = cipherTxt[k++];
        }
    }

    for(i=1;i<blocks;i++)
    {
        for(j=0;j<BLOCKSIZE;j++)
        {
            ciphert[j] = cipherTextTemp[i][j];
        }
    
        BF_ecb_encrypt((unsigned char*) ciphert, (unsigned char*) plaint, key, BF_DECRYPT);
    
        for(j=0;j<BLOCKSIZE;j++)
        {
            ciphert[j] = plaint[j]^cipherTextTemp[i-1][j];
        }      
    
        for(j = 0; j < BLOCKSIZE; j++)
        {
            plainText[length++] = ciphert[j];
//          printf("%02x ", outbuf[i]);     // Hex Value
        }
    }

    *resultlen = length+1;
    
    if(length<8)
    {
        return (void *)plainText;
    }

    //Removing the padded characters logic
    int paddedChar = plainText[length-2] - '0';
    length--;

    //printf("length  = %d\n", length);
    
    for(i= 0;i<length-1;i++)
    {
        tempi++;
        if(plainText[i] - '0' == paddedChar)
        {
            flag=1;
            break;
        }
    }
    
    if(flag == 1)
    {
        //printf("in IF part");
        length = tempi -1;
        for(i=0;i<length;i++)
        {
            finalPlainText[i] = plainText[i];
//            printf("In for loop i = %d = %c\n",b,finalPlainText[b]);
        }
        *resultlen = length+1;
        free(key);
        free(plainText);
        free(plainTextTemp);
        free(finalPlainText);
        return (void *)finalPlainText;
    }
    else
    {

        size_t length1 =  strlen((char*)plainText);
        length1 = length1 -2;
        for(i=0;i<length1;i++)
        {
            finalPlainText[i] = plainText[i];
        }
        *resultlen = length1+1;
        free(key);
        free(plainText);
        free(plainTextTemp);
        free(finalPlainText);
        return (void *)finalPlainText;
    }

}

//--------------------------------------------------------------------------------------------------------------------------