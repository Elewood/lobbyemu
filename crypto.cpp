#include <string.h>
#include <stdio.h>
#include "pidata.h"
#include "crypto.h"

/**
 * "hackOnline" Default Key Blowfish Constructor
 */
Crypto::Crypto()
{
	// Forward Call
	PrepareStructure((uint8_t *)"hackOnline", 10);
}

/**
 * Custom Key Blowfish Constructor
 * @param key Key Buffer
 * @param keyLen Key Buffer Length (in Bytes)
 */
Crypto::Crypto(uint8_t * key, uint32_t keyLen)
{
	// Forward Call
	PrepareStructure(key, keyLen);
}

/**
 * Calculates the Blowfish S-Boxes & Pi-Tables from the given Key
 * @param key Key Buffer
 * @param keyLen Key Buffer Length (in Bytes)
 */
void Crypto::PrepareStructure(uint8_t * key, uint32_t keyLen)
{
	// Allocate Memory
	secretKey = new uint8_t[keyLen];
	sBoxes = new uint32_t*[4];
	pArray = new uint32_t[18];
	for(uint32_t i = 0; i < 4; i++)
	{
		sBoxes[i] = new uint32_t[256];
	}

	// Initialize Fields
	memcpy(secretKey, key, keyLen);
	secretKeyLength = keyLen;
	memcpy((void *)sBoxes[0], &default_sboxes[0], sizeof(default_sboxes) / 4);
	memcpy((void *)sBoxes[1], &default_sboxes[256], sizeof(default_sboxes) / 4);
	memcpy((void *)sBoxes[2], &default_sboxes[512], sizeof(default_sboxes) / 4);
	memcpy((void *)sBoxes[3], &default_sboxes[768], sizeof(default_sboxes) / 4);
	memcpy((void *)pArray, default_parray, sizeof(default_parray));

	// Mix Key into P-Array
	for(uint32_t i = 0; i < 18; i++)
	{
		// Roll Key on Edge
		uint32_t rolledKey = 0;
		uint8_t * rolledKeyBytes = (uint8_t *)&rolledKey;
		for(uint32_t j = 0; j < sizeof(rolledKey); j++)
		{
			rolledKeyBytes[sizeof(rolledKey) - j - 1] = key[(i * sizeof(uint32_t) + j) % keyLen];
		}

		// XOR P-Array Entry with Rolled Key
		pArray[i] ^= rolledKey;
	}

	// Encrypt P-Array
	uint32_t tempChunks[2] = { 0, 0 };
	for(uint32_t i = 0; i < 9; i++)
	{
		// Encrypt 1st Half
		tempChunks[0] ^= pArray[0];
		tempChunks[1] ^= pArray[1] ^ rotateDword(&tempChunks[0]);
		tempChunks[0] ^= pArray[2] ^ rotateDword(&tempChunks[1]);
		tempChunks[1] ^= pArray[3] ^ rotateDword(&tempChunks[0]);
		tempChunks[0] ^= pArray[4] ^ rotateDword(&tempChunks[1]);
		tempChunks[1] ^= pArray[5] ^ rotateDword(&tempChunks[0]);
		tempChunks[0] ^= pArray[6] ^ rotateDword(&tempChunks[1]);
		tempChunks[1] ^= pArray[7] ^ rotateDword(&tempChunks[0]);
		tempChunks[0] ^= pArray[8] ^ rotateDword(&tempChunks[1]);

		// Encrypt 2nd Half
		swap(&tempChunks[1], &tempChunks[0], 9);
		swap(&tempChunks[0], &tempChunks[1], 10);
		swap(&tempChunks[1], &tempChunks[0], 11);
		swap(&tempChunks[0], &tempChunks[1], 12);
		swap(&tempChunks[1], &tempChunks[0], 13);
		swap(&tempChunks[0], &tempChunks[1], 14);
		swap(&tempChunks[1], &tempChunks[0], 15);
		swap(&tempChunks[0], &tempChunks[1], 16);

		// Write Data to P-Array
		pArray[i * 2] = pArray[17] ^ tempChunks[1];
		pArray[i * 2 + 1] = tempChunks[0];

		// Read Data for next Cycle
		tempChunks[0] = pArray[i * 2];
		tempChunks[1] = pArray[i * 2 + 1];
	}

	// Encrypt S-Boxes
	for(uint32_t i = 0; i < 4; i++)
	{
		// Encrypt S-Box
		for(uint32_t j = 0; j < 256; j += 2)
		{
			// Encrypt Data
			tempChunks[0] ^= pArray[0];
			tempChunks[1] ^= pArray[1] ^ rotateDword(&tempChunks[0]);
			swap(&tempChunks[0], &tempChunks[1], 2);
			swap(&tempChunks[1], &tempChunks[0], 3);
			swap(&tempChunks[0], &tempChunks[1], 4);
			swap(&tempChunks[1], &tempChunks[0], 5);
			swap(&tempChunks[0], &tempChunks[1], 6);
			swap(&tempChunks[1], &tempChunks[0], 7);
			swap(&tempChunks[0], &tempChunks[1], 8);
			swap(&tempChunks[1], &tempChunks[0], 9);
			swap(&tempChunks[0], &tempChunks[1], 10);
			swap(&tempChunks[1], &tempChunks[0], 11);
			swap(&tempChunks[0], &tempChunks[1], 12);
			swap(&tempChunks[1], &tempChunks[0], 13);
			swap(&tempChunks[0], &tempChunks[1], 14);
			swap(&tempChunks[1], &tempChunks[0], 15);
			swap(&tempChunks[0], &tempChunks[1], 16);
			
			// Write Data to S-Box
			sBoxes[i][j] = pArray[17] ^ tempChunks[1];
			sBoxes[i][j + 1] = tempChunks[0];

			// Read Data for next Cycle
			tempChunks[0] = sBoxes[i][j];
			tempChunks[1] = sBoxes[i][j + 1];
		}
	}
}

/**
 * Blowfish Crypto Destructor
 */
Crypto::~Crypto()
{
	// Free Memory
	delete[] pArray;
	for(int i = 0; i < 4; i++)
	{
		delete[] sBoxes[i];
	}
	delete[] sBoxes;
	delete[] secretKey;
}

/**
 * Returns the length of the currently set Blowfish Key Buffer
 * @return Key Buffer Length (in Bytes)
 */
uint32_t Crypto::GetKeyLength()
{
	// Return Secret Key Length
	return secretKeyLength;
}

/**
 * Returns the current set Blowfish Key Buffer
 * @return Key Buffer
 */
uint8_t * Crypto::GetKey()
{
	// Return Secret Key
	return secretKey;
}

/**
 * Decrypts Data using Blowfish
 * @param payload Encrypted Payload
 * @param payload_length Encrypted Payload Length (in Bytes)
 * @param output Decrypted Payload Output Buffer
 * @param output_length Decrypted Payload Output Buffer Length (in Bytes, gets set to processed length if decryption was successful)
 * @return Decrypt Result
 */
int Crypto::Decrypt(const uint8_t * payload, uint32_t payload_length, uint8_t * output, uint32_t * output_length)
{
	// Output Buffer not available
	if (output == NULL) return 0;

	// Invalid Payload Alignment / Size (has to be a multiple of 8)
	if (payload_length & 7) return 0;

	// Output Buffer too small
	if (*output_length < payload_length) return 0;

	// Copy Payload into Output Buffer
	memcpy(output, payload, payload_length);

	// Decrypt Payload
	for(uint32_t i = 0; i < payload_length >> 3; i++)
	{
		// Cast Buffer for use as a Chunk Pointer
		uint32_t * chunkBuffer = ((uint32_t *)output) + 2 * i;

		// Processing Variables
		uint32_t runningChunk = 0;
		uint32_t tempChunks[2] = { 0, 0 };

		// Decrypt Chunk
		runningChunk = chunkBuffer[0] ^ pArray[17];
		tempChunks[0] = runningChunk;
		runningChunk = chunkBuffer[1] ^ pArray[16] ^ rotateDword(&runningChunk);
		tempChunks[1] = runningChunk;
		runningChunk = pArray[15] ^ rotateDword(&runningChunk) ^ tempChunks[0];
		tempChunks[0] = runningChunk;
		runningChunk = pArray[14] ^ rotateDword(&runningChunk) ^ tempChunks[1];
		tempChunks[1] = runningChunk;
		runningChunk = pArray[13] ^ rotateDword(&runningChunk) ^ tempChunks[0];
		tempChunks[0] = runningChunk;
		runningChunk = pArray[12] ^ rotateDword(&runningChunk) ^ tempChunks[1];
		tempChunks[1] = runningChunk;
		runningChunk = pArray[11] ^ rotateDword(&runningChunk) ^ tempChunks[0];
		tempChunks[0] = runningChunk;
		runningChunk = pArray[10] ^ rotateDword(&runningChunk) ^ tempChunks[1];
		tempChunks[1] = runningChunk;
		runningChunk = pArray[9] ^ rotateDword(&runningChunk) ^ tempChunks[0];
		tempChunks[0] = runningChunk;
		runningChunk = pArray[8] ^ rotateDword(&runningChunk) ^ tempChunks[1];
		tempChunks[1] = runningChunk;
		runningChunk = pArray[7] ^ rotateDword(&runningChunk) ^ tempChunks[0];
		tempChunks[0] = runningChunk;
		runningChunk = pArray[6] ^ rotateDword(&runningChunk) ^ tempChunks[1];
		tempChunks[1] = runningChunk;
		runningChunk = pArray[5] ^ rotateDword(&runningChunk) ^ tempChunks[0];
		tempChunks[0] = runningChunk;
		runningChunk = pArray[4] ^ rotateDword(&runningChunk) ^ tempChunks[1];
		tempChunks[1] = runningChunk;
		runningChunk = pArray[3] ^ rotateDword(&runningChunk) ^ tempChunks[0];
		tempChunks[0] = runningChunk;
		runningChunk = pArray[2] ^ rotateDword(&runningChunk) ^ tempChunks[1];
		tempChunks[1] = runningChunk;
		runningChunk = pArray[1] ^ rotateDword(&runningChunk) ^ tempChunks[0];

		// Save Plaintext Chunk
		chunkBuffer[0] = pArray[0] ^ tempChunks[1];
		chunkBuffer[1] = runningChunk;
	}

	// Set Output Buffer Length
	*output_length = payload_length;

	// Successfully decrypted Payload
	return 1;
}

/**
 * Encrypts Data using Blowfish
 * @param payload Decrypted Payload
 * @param payload_length Decrypted Payload Length (in Bytes)
 * @param output Encrypted Payload Output Buffer
 * @param output_length Encrypted Payload Output Buffer Length (in Bytes, gets set to processed length if encryption was successful)
 * @return Encrypt Result
 */
int Crypto::Encrypt(const uint8_t * payload, uint32_t payload_length, uint8_t * output, uint32_t * output_length)
{
	// Output Buffer not available
	if (output == NULL) return 0;

	// Invalid Payload Alignment / Size (has to be a multiple of 8)
	if (payload_length & 7) return 0;

	// Output Buffer too small
	if (*output_length < payload_length) return 0;

	// Copy Payload into Output Buffer
	memcpy(output, payload, payload_length);

	// Encrypt Payload
	for(uint32_t i = 0; i < payload_length >> 3; i++)
	{
		// Cast Buffer for use as a Chunk Pointer
		uint32_t * chunkBuffer = ((uint32_t *)output) + 2 * i;

		// Processing Variables
		uint32_t runningChunk = 0;
		uint32_t tempChunks[2] = { 0, 0 };

		// Encrypt Chunk
		runningChunk = chunkBuffer[0] ^ pArray[0];
		tempChunks[0] = runningChunk;
		runningChunk = chunkBuffer[1] ^ pArray[1] ^ rotateDword(&runningChunk);
		tempChunks[1] = runningChunk;
		runningChunk = pArray[2] ^ rotateDword(&runningChunk) ^ tempChunks[0];
		tempChunks[0] = runningChunk;
		runningChunk = pArray[3] ^ rotateDword(&runningChunk) ^ tempChunks[1];
		tempChunks[1] = runningChunk;
		runningChunk = pArray[4] ^ rotateDword(&runningChunk) ^ tempChunks[0];
		tempChunks[0] = runningChunk;
		runningChunk = pArray[5] ^ rotateDword(&runningChunk) ^ tempChunks[1];
		tempChunks[1] = runningChunk;
		runningChunk = pArray[6] ^ rotateDword(&runningChunk) ^ tempChunks[0];
		tempChunks[0] = runningChunk;
		runningChunk = pArray[7] ^ rotateDword(&runningChunk) ^ tempChunks[1];
		tempChunks[1] = runningChunk;
		runningChunk = pArray[8] ^ rotateDword(&runningChunk) ^ tempChunks[0];
		tempChunks[0] = runningChunk;
		runningChunk = pArray[9] ^ rotateDword(&runningChunk) ^ tempChunks[1];
		tempChunks[1] = runningChunk;
		runningChunk = pArray[10] ^ rotateDword(&runningChunk) ^ tempChunks[0];
		tempChunks[0] = runningChunk;
		runningChunk = pArray[11] ^ rotateDword(&runningChunk) ^ tempChunks[1];
		tempChunks[1] = runningChunk;
		runningChunk = pArray[12] ^ rotateDword(&runningChunk) ^ tempChunks[0];
		tempChunks[0] = runningChunk;
		runningChunk = pArray[13] ^ rotateDword(&runningChunk) ^ tempChunks[1];
		tempChunks[1] = runningChunk;
		runningChunk = pArray[14] ^ rotateDword(&runningChunk) ^ tempChunks[0];
		tempChunks[0] = runningChunk;
		runningChunk = pArray[15] ^ rotateDword(&runningChunk) ^ tempChunks[1];
		tempChunks[1] = runningChunk;
		runningChunk = pArray[16] ^ rotateDword(&runningChunk) ^ tempChunks[0];

		// Save Plaintext Chunk
		chunkBuffer[0] = pArray[17] ^ tempChunks[1];
		chunkBuffer[1] = runningChunk;
	}

	// Set Output Buffer Length
	*output_length = payload_length;

	// Successfully decrypted Payload
	return 1;
}

/**
 * Blowfish DWORD Rotator
 * @param value Input Value
 * @return Output Value
 */
int Crypto::rotateDword(uint32_t * value)
{
	// Cast as Bytes
	uint8_t * val8 = (uint8_t *)value;

	// Magic Bit Juggling (sacrifice a chicken, pray to satan, wake the dead, etc.)
	return sBoxes[3][val8[0]] + (sBoxes[2][val8[1]] ^ (sBoxes[0][val8[3]] + sBoxes[1][val8[2]]));
}

/**
 * Blowfish Pi-Table Swapper
 * @param L Left DWORD Reference (Input & Result Output)
 * @param R Right DWORD Reference
 * @param P Pi-Table Index
 */
void Crypto::swap(uint32_t * L, uint32_t * R, uint32_t P)
{
	// Magic Bit Juggling (sacrifice a chicken, pray to satan, wake the dead, etc.)
	*L ^= pArray[P] ^ rotateDword(R);
}

/**
 * Generate Fragment Checksum
 * @param payload Buffer
 * @param payload_length Buffer Length (in Bytes)
 * @return Checksum
 */
uint16_t Crypto::Checksum(const uint8_t * payload, uint32_t payload_length)
{
	// Calculate Number of DWORD Chunks
	uint32_t dwordChunks = payload_length >> 2;

	// Calculate Number of BYTE Chunks
	uint32_t byteChunks = payload_length & 3;

	// DWORD Payload Pointer
	uint32_t * payload32 = (uint32_t *)payload;

	// Resulting Checksum
	uint32_t checksum = 0;

	// BYTE Checksum Pointer
	uint8_t * checksum8 = (uint8_t *)&checksum;

	// Iterate DWORD Chunks
	for(uint32_t i = 0; i < dwordChunks; i++)
	{
		// XOR Chunk into Checksum
		checksum ^= payload32[i];
	}

	// Iterate BYTE Chunks
	for(uint32_t i = 0; i < byteChunks; i++)
	{
		// XOR Chunk into Checksum
		checksum8[0] ^= payload[dwordChunks * sizeof(uint32_t) + i];
	}
	
	// XOR Final Checksum
	checksum = (checksum >> 16) ^ checksum;

	// Return Checksum
	return checksum & 0xFFFF;
}
