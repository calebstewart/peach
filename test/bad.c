/*
* @Author: Caleb Stewart
* @Date:   2016-05-31 16:42:45
* @Last Modified by:   Caleb Stewart
* @Last Modified time: 2016-05-31 17:33:59
*/
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv)
{
	if( strcmp(argv[1], "WAIT") == 0 ){
		while( 1 );
	}
	*((int*)(0x0)) = 0xDEADBEEF;
	return 0;
} 
