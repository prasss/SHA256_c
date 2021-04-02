/*
 * sha256.h
 *
 *  Created on: 21-Nov-2020
 *      Author: prasanna
 */
#include <inttypes.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdint.h>

/*
 * Struct buffer_manager
 * This struct is used to store the the whole data string and the length of the whole data string
 * additionally we also use this struct to store the remaining length of the data string that is yet
 * to be processed through the SHA-256 algorithm
 */
typedef struct buffer_manager {
	const uint8_t * masterData;
	size_t Remaininglen;
	size_t total_len;
	int oneMoreRound;
}buffer_t;

/*
 * The function printBitStream() is used to readily print the bitstream in form of Hex values
 * \param uint8_t* msg		: IN
 * \param int size			: IN
 */
void printBitStream(uint8_t* msg, int size);

/*
 * The function dataPadding() is used to pad the data provided to it according to the padding rules
 * that are applicable fo the SHA-256 algorithm. It varies according to the number of Bits provided.
 * \param uint8_t* paddedString		: INOUT
 * \param buffer_t * buff			: IN
 * \param int len					: IN
 */
void dataPadding(uint8_t* paddedString, int len, buffer_t * buff);

/*
 * The function leftRotate() is used to perform the Left Rotate operation for the data bits by 'n' times
 * \param uint32_t input		: IN
 * \param unsigned int n					: IN
 * \return uint32_t
 */
uint32_t leftRotate(uint32_t input, unsigned int n);

/*
 * The function rightRotate() is used to perform the Right Rotate operation for the data bits by 'n' times
 * \param uint32_t input		: IN
 * \param int n					: IN
 * \return uint32_t
 */
uint32_t rightRotate(uint32_t input, unsigned int n);

/*
 * The function calcMySHA256() is the main function that is running the SHA-256 algorithm and this function
 * also calls the dataPadding() function when we require padding to be done on the individual data sets for
 * each round of the SHA-256 operation
 * \param uint8_t *input		: IN
 * \param uint8_t *hashOp		: OUT
 * \param int lenOfData			: IN
 */
void calcMySHA256(uint8_t *input, uint8_t *hashOp, int lenOfData);

/*
 * The function printMySHA256() is used to print the final SHA-256 output on the Console
 * \param uint8_t *hashOp			: IN
 * \param char opString[65]			: IN
 */
void printMySHA256(uint8_t *hashOp, char opString[65]);
