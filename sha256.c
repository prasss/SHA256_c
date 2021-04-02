/*
 * sha.c
 *
 *  Created on: 22-Nov-2020
 *      Author: prasanna
 */

#include "sha256.h"
//#include <global.h>

#include <stdio.h>
#include <string.h>

int masterDataLength = 0;


uint32_t Kt[] = {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

uint32_t H[] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};



void printBitStream(uint8_t* msg, int size){

	for (int var = 0; var < size; var++) {

		unsigned char temp = (unsigned) msg[var];
		printf("%02X", temp);
//		if(var % 4 == 0){
//			printf("\n");
//		}
	}
	printf("\n");
}



void dataPadding(uint8_t* paddedString, int len, buffer_t * buff){

	size_t spaceAfterBits;

	if(buff->Remaininglen > 64){

		memcpy(paddedString, buff->masterData, 64);
		paddedString += len;
		buff->masterData += 64;

		buff->Remaininglen -= 64;
	}
	else{

	size_t paddingBytesLeft = 64 - buff->Remaininglen;	//len(padded data) - len(msg) - len(msglength)

	size_t length = buff->Remaininglen*8;
	size_t totalLength = buff->total_len*8;

	printf("last packet length: %zu\n",buff->Remaininglen);


	memcpy(paddedString, buff->masterData, buff->Remaininglen);
	paddedString += buff->Remaininglen;

	*paddedString++ = 0x80;
	paddingBytesLeft--;


	if(paddingBytesLeft >= 8){

		memset(paddedString, 0x00, paddingBytesLeft - 8);
		paddedString += (int)(paddingBytesLeft - 8);

		for(int i = 7; i>= 0; i--){
			*paddedString++ = totalLength >> ((8*i) & 0xff);

//			memset(paddedString, length >> ((8*i) & 0xff), 1);
//			paddedString +=1;
				}
		}
	else{
		memset(paddedString, 0x00, paddingBytesLeft);
	}

	buff->Remaininglen = 0;
	}

//	*paddedString ++ = length >> 8*7 & 0xFF;
//	*paddedString ++ = length >> 8*6 & 0xFF;
//	*paddedString ++ = length >> 8*5 & 0xFF;
//	*paddedString ++ = length >> 8*4 & 0xFF;
//	*paddedString ++ = length >> 8*3 & 0xFF;
//	*paddedString ++ = length >> 8*2 & 0xFF;
//	*paddedString ++ = length >> 8*1 & 0xFF;
//	*paddedString ++ = length >> 8*0 & 0xFF;
//	paddedString[7] = len;
//

}

void calcMySHA256(uint8_t *input, uint8_t *hashOp, int lenOfData){


	uint32_t workingVars[8];
	uint8_t dataPadded[64];

	struct buffer_manager buff;

	buff.masterData = input;
	buff.Remaininglen = lenOfData;
	buff.total_len = lenOfData;
	buff.oneMoreRound = 0;

	do{

	dataPadding(dataPadded, lenOfData, &buff);

	printBitStream(dataPadded, 64*sizeof(char));

	uint8_t *WData = dataPadded;
//
//	printf("lengthOfString: %zu\n", lengthOfString);
	//setup the starting data for the message digest
	//also to be used from the previous block if available
	for (uint8_t i = 0; i < 8; i++){
		workingVars[i] = H[i];
	}

	for (uint8_t i = 0; i < 4; i++) {

		//message digest, to be calculated 16 at a time
		uint32_t w[16];

		for (uint8_t j = 0; j < 16; j++) {
				if (i == 0) {
					//store the data units from WData into the w array, iteratively,
					//as the WData pointer is incremented successively after every entry
					//inside this if condition

					w[j] = 	(uint32_t) WData[0] << 24 |
							(uint32_t) WData[1] << 16 |
							(uint32_t) WData[2] << 8  |
							(uint32_t) WData[3];
					WData += 4; 	//increment pointer
					printf("w[%d]: %x ", i*16+j, w[j]);
				}
				else{
					//lsigma0 = ROR(1, 7) XOR ROR(1, 18) XOR SHR(1, 3)
					//here 0xf means 0x0000000F bit masking, to ensure that the number doesn't go beyond 15 i.e 0x0f
					uint32_t lsigma0 = rightRotate(w[(j + 1) & 0xf], 7) ^ rightRotate(w[(j + 1) & 0xf], 18) ^ (w[(j + 1) & 0xf] >> 3);

					//lsigma1 = ROR(1, 17) XOR ROR(1, 19) XOR SHR(1, 10)
					//here 0xf means 0x0000000F bit masking, to ensure that the number doesn't go beyond 15 i.e 0x0f
					uint32_t lsigma1 = rightRotate(w[(j + 14) & 0xf], 17) ^ rightRotate(w[(j + 14) & 0xf], 19) ^ (w[(j + 14) & 0xf] >> 10);

					//w[0] + lsigma0[1] + w[9] + lsigma1[14] OR w[t - 16] + lsigma0[t - 15] + w[1 - 7] + lsigma1[t - 2]
					w[j] = w[j] + lsigma0 + w[(j + 9) & 0xf] + lsigma1;
					printf("\nw[%d]: %x ", i*16+j, w[j]);
					printf("lsigma0: %x, lsigma1: %x, ", lsigma0, lsigma1);
				}


				//usigma1 = ROR(e, 6) XOR ROR(e, 11) XOR ROR(e, 25)
				uint32_t usigma1 = rightRotate(workingVars[4], 6) ^ rightRotate(workingVars[4], 11) ^ rightRotate(workingVars[4], 25);

				//choice = (e & f) XOR ((not e) & g)
				uint32_t choice = (workingVars[4] & workingVars[5]) ^ (~workingVars[4] & workingVars[6]);

				uint32_t t1 = workingVars[7] + usigma1 + choice + Kt[i << 4 | j] + w[j];

				//usigma1 = ROR(a, 2) XOR ROR(a, 13) XOR ROR(a, 22)
				uint32_t usigma0 = rightRotate(workingVars[0], 2) ^ rightRotate(workingVars[0], 13) ^ rightRotate(workingVars[0], 22);

				//(a & b) XOR (a &&d c) XOR (b & c)
				uint32_t major = (workingVars[0] & workingVars[1]) ^ (workingVars[0] & workingVars[2]) ^ (workingVars[1] & workingVars[2]);

				uint32_t t2 = usigma0 + major;

//				printf("usigma0: %x, usigma1: %x, choice: %x, major: %x, t1: %x, t2: %x\n", usigma0, usigma1, choice, major, t1, t2);


				workingVars[7] = workingVars[6];
				workingVars[6] = workingVars[5];
				workingVars[5] = workingVars[4];
				workingVars[4] = workingVars[3] + t1;
				workingVars[3] = workingVars[2];
				workingVars[2] = workingVars[1];
				workingVars[1] = workingVars[0];
				workingVars[0] = t1 + t2;

			}

	}

	//H[i] = H[i] + workingVars[i]
	//also to be used for next block if required
	for (uint8_t i = 0; i < 8; i++){
			H[i] += workingVars[i];
	}

	uint8_t j = 0;

	// Produce the BigEndian output of 256 bits as required
	// the 32 bits are broken down into a 8bit array, to be used later
	for (uint8_t i = 0; i < 8; i++)
	{
		hashOp[j++] = (uint8_t) (H[i] >> 24);
		hashOp[j++] = (uint8_t) (H[i] >> 16);
		hashOp[j++] = (uint8_t) (H[i] >> 8);
		hashOp[j++] = (uint8_t)  H[i];
	}

	}while(buff.Remaininglen > 0 || buff.oneMoreRound);
}

void printMySHA256(uint8_t *hashOp, char opString[64]){

	uint8_t i;
	int stringAppend;

	for (i = 0; i < 32; i++) {
		stringAppend = sprintf(opString, "%02X", hashOp[i]);	//sprintf returns the number of characters
		opString += stringAppend;
	}
}



uint32_t leftRotate(uint32_t input, unsigned int n){

	return (unsigned)(input << n) | (input >> (32 - n));
}

uint32_t rightRotate(uint32_t input, unsigned int n){

	return (unsigned)(input >> n) | (input << (32 - n));
}
