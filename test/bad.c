/*
* @Author: Caleb Stewart
* @Date:   2016-05-31 16:42:45
* @Last Modified by:   Caleb Stewart
* @Last Modified time: 2016-05-31 16:43:22
*/
#include <stdio.h>

int main(int argc, char** argv)
{
	*((int*)(0x0)) = 0xDEADBEEF;
	return 0;
} 
