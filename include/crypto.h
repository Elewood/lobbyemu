#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdint.h>

class Crypto
{
	private:

	// Blowfish Secret Key
	uint8_t * secretKey;

	// Blowfish Secret Key Length
	uint32_t secretKeyLength;

	// Blowfish S-Boxes
	uint32_t ** sBoxes;
	
	// Blowfish P-Array
	uint32_t * pArray;

	/**
	 * Blowfish DWORD Rotator
	 * @param value Input Value
	 * @return Output Value
	 */
	int rotateDword(uint32_t * value);

	/**
	 * Blowfish Pi-Table Swapper
	 * @param L Left DWORD Reference (Input & Result Output)
	 * @param R Right DWORD Reference
	 * @param P Pi-Table Index
	 */
	void swap(uint32_t * L, uint32_t * R, uint32_t P);

	/**
	 * Calculates the Blowfish S-Boxes & Pi-Tables from the given Key
	 * @param key Key Buffer
	 * @param keyLen Key Buffer Length (in Bytes)
	 */
	void PrepareStructure(uint8_t * key, uint32_t keyLen);

	public:
	
	/**
	 * "hackOnline" Default Key Blowfish Constructor
	 */
	Crypto();
	
	/**
	 * Custom Key Blowfish Constructor
	 * @param key Key Buffer
	 * @param keyLen Key Buffer Length (in Bytes)
	 */
	Crypto(uint8_t * key, uint32_t keyLen);
	
	/**
	 * Blowfish Crypto Destructor
	 */
	~Crypto();
	
	/**
	 * Returns the length of the currently set Blowfish Key Buffer
	 * @return Key Buffer Length (in Bytes)
	 */
	uint32_t GetKeyLength();

	/**
	 * Returns the current set Blowfish Key Buffer
	 * @return Key Buffer
	 */
	uint8_t * GetKey();

	/**
	 * Decrypts Data using Blowfish
	 * @param payload Encrypted Payload
	 * @param payload_length Encrypted Payload Length (in Bytes)
	 * @param output Decrypted Payload Output Buffer
	 * @param output_length Decrypted Payload Output Buffer Length (in Bytes, gets set to processed length if decryption was successful)
	 * @return Decrypt Result
	 */
	int Decrypt(const uint8_t * payload, uint32_t payload_length, uint8_t * output, uint32_t * output_length);

	/**
	 * Encrypts Data using Blowfish
	 * @param payload Decrypted Payload
	 * @param payload_length Decrypted Payload Length (in Bytes)
	 * @param output Encrypted Payload Output Buffer
	 * @param output_length Encrypted Payload Output Buffer Length (in Bytes, gets set to processed length if encryption was successful)
	 * @return Encrypt Result
	 */
	int Encrypt(const uint8_t * payload, uint32_t payload_length, uint8_t * output, uint32_t * output_length);

	/**
	 * Generate Fragment Checksum
	 * @param payload Buffer
	 * @param payload_length Buffer Length (in Bytes)
	 * @return Checksum
	 */
	static uint16_t Checksum(const uint8_t * payload, uint32_t payload_length);
};

#endif

