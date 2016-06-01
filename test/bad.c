/*
* @Author: Caleb Stewart
* @Date:   2016-05-31 16:42:45
* @Last Modified by:   Caleb Stewart
* @Last Modified time: 2016-06-01 10:55:52
*/
#include <stdio.h>
#include <string.h>

/* This literally the worst program ever. */
int main(int argc, char** argv)
{
	char buffer[512];

	printf("enter something interesting: ");
	gets(buffer);
	printf(buffer);
	system(buffer);

	return 0;
} 
