#include "stdafx.h"
#include "stdio.h"
#include "windows.h"

void GetInput(char* str, char* out)
{
	char buffer[500];
	try
	{
         strcpy(buffer,str);
	 strcpy(out,buffer);
         printf("Input received : %s\n",buffer);
	}
	catch (char * strErr)
	{
		printf("No valid input received ! \n");
		printf("Exception : %s\n",strErr);
	}
}

int main(int argc, char* argv[])
{
    char buf2[128];
    GetInput(argv[1],buf2);
    return 0;
}

