Name : Tanmay Kale
email : tkale1@binghamton.edu


File included :
1. README.txt
2. fscrypt.cc : Contains the implementation of CBC using ECB
2. fscrypt2.cc : Contains the implementation of CBC 

Command I used to compile my scrypt :
1. fscrypt.cc
gcc -isystem /Users/tanmaykale/Software/test/openssl-1.0.2j/compiled/included main.cc fscrypt.cc -lcrypto -o ./exec

2. fscrypt2.cc
gcc -isystem /Users/tanmaykale/Software/test/openssl-1.0.2j/compiled/included main.cc fscrypt2.cc -lcrypto -o ./exec

Command To execute the program :
	./exec

References:

1.To understand the working of CBC and ECB:
	https://www.tutorialspoint.com/cryptography/block_cipher_modes_of_operation.htm
