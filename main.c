/*
 * main.c
 *
 *  Created on: 20-Nov-2020
 *      Author: prasanna
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sha256.h"

//use these #defines to control the include guards to enable reading from string or from file.
#define READ_FROM_STRING 0
#define READ_FROM_FILE 1


#if READ_FROM_STRING
	#define DATA_STRING "abc"
#endif

#if READ_FROM_FILE
	#define FILE_NAME "myFile.txt"
#endif



int main(){

#if READ_FROM_FILE
	FILE *fp;
	uint8_t data[448];

	fp = fopen(FILE_NAME, "r");
	fscanf(fp, "%s", data);
	printf("file contents: %s\n", data);
#endif

//	uint8_t dataPadded[64];
//	uint8_t u_data[64];
	uint8_t hashOp[32];
	char opString[64];

#if READ_FROM_STRING

	char * data = DATA_STRING;
	printf("string contents: %s\n", data);
#endif



	int length = (int)strlen(data);

//	memcpy(u_data, data, length);

	printf("lengthOfString: %d Bytes and %d Bits\n", length, length*8);


//	dataPadding(dataPadded, length, data);
//
//	printBitStream(dataPadded, 64*sizeof(char));

	calcMySHA256(data, hashOp, length);

	printMySHA256(hashOp, opString);

	printf("SHA-256 hash: %s", opString);


	return 0;
}





