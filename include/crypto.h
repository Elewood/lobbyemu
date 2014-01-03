#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdint.h>

class Crypto
{
	private:

	// Blowfish S-Boxes
	uint32_t ** sBoxes;
	
	// Blowfish P-Array
	uint32_t * pArray;

	// Rotator
	int rotateDword(uint32_t * value);

	// Swapper
	void swap(uint32_t * L, uint32_t * R, uint32_t P);

	// Constructor Helper
	void PrepareStructure(uint8_t * key, uint32_t keyLen);

	public:
	
	// Constructor
	Crypto();
	
	// Alternative Constructor
	Crypto(uint8_t * key, uint32_t keyLen);
	
	// Destructor
	~Crypto();
	
	// Decrypts Data using Blowfish
	int Decrypt(const uint8_t * payload, uint32_t payload_length, uint8_t * output, uint32_t * output_length);

	// Encrypts Data using Blowfish
	int Encrypt(const uint8_t * payload, uint32_t payload_length, uint8_t * output, uint32_t * output_length);

	// Checksum Generator
	uint16_t Checksum(const uint8_t * payload, uint32_t payload_length);
};

#endif

