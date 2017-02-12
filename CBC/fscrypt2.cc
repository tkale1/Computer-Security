#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "openssl/blowfish.h"

const int BLOCKSIZE = 8;

void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen){

	// set up the key.
	BF_KEY *key = (BF_KEY*) malloc(sizeof(BF_KEY));
    int keylength = strlen(keystr);
	BF_set_key(key, strlen(keystr),(unsigned char*) keystr);

	// Copying the plain text into temp.
	unsigned char *temp = (unsigned char *) malloc(bufsize--);
	memcpy(temp,(unsigned char *) plaintext,bufsize);
	
	int blocks = (bufsize)%BLOCKSIZE; 
	int strLength = 0,i=0,j=0,padLength=0,totalLength=0,bufTemp=0;

	if(blocks > 0)
	{
		strLength = (bufsize)%BLOCKSIZE;
		padLength=BLOCKSIZE-strLength;
	}
	//total length = buffersize plus the padding bits needed to make the data into Bytes.
	totalLength=bufsize+padLength;
	// printf("buffer size : %d\n",bufsize );
	// printf("totalLength = %d  padLength = %d  BLOCKSIZE = %d  strLength = %d\n", totalLength,padLength,BLOCKSIZE,strLength);
	
	unsigned char pt[totalLength];
	unsigned char *cipherText = (unsigned char *) malloc((totalLength)*sizeof(unsigned char));
	
	//Initializing the Initializing vector iv with '0'.
	unsigned char *iv = (unsigned char*) malloc(sizeof(unsigned char));
	for(i=0;i<BLOCKSIZE;i++)
	{
		iv[i] = '0';
	}
	
	for(j=0;j<bufsize;j++)
	{
			pt[j]=temp[j];
	}

	//padding extra bits after the orginal text is copied. i.e if strlen = 3. then pad 5 bits.
	bufTemp=bufsize;
	for(j= 0 ; j < padLength; j++)
	{
		pt[bufTemp++] = padLength + '0';
	}

	BF_cbc_encrypt((unsigned char *) pt, (unsigned char *) cipherText, bufsize, key, iv, BF_ENCRYPT);
	*resultlen = totalLength;
	free(key);
	free(iv);
	return (void *) cipherText;	
}

void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen){
	
	unsigned char *plainText = (unsigned char *) malloc(bufsize*sizeof(unsigned char));
	plainText = (unsigned char *) ciphertext;
	int i=0;	

	//set up the key.
	BF_KEY *key = (BF_KEY*) malloc(sizeof(BF_KEY));
    int keylength = strlen(keystr);
	BF_set_key(key, strlen(keystr),(unsigned char*) keystr);

	//Initializing the Initializing vector iv with '0'.
	unsigned char *iv = (unsigned char*) malloc(sizeof(unsigned char));
	for(i=0;i<BLOCKSIZE;i++)
	{
		iv[i] = '0';
	}
	BF_cbc_encrypt((unsigned char*) plainText, (unsigned char*) plainText, bufsize, key, iv, BF_DECRYPT);

	//printf("length = %lu\n", strlen((char *)plainText));
	*resultlen = strlen((char *)plainText)+1;
	free(key);
	free(iv);
	return (void *) plainText;

}
