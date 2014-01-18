#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdlib.h>
#include "opcode.h"
#include "client.h"

Client::Client(int socket)
{
	// Save Socket
	this->socket = socket;

	// Initialize RX Buffer
	this->rxBufferPosition = 0;
	this->rxBufferLength = 2048;
	this->rxBuffer = new uint8_t[this->rxBufferLength];

	// Create Cryptography Objects
	for(uint32_t i = 0; i < 4; i++) crypto[i] = NULL;
	crypto[0] = new Crypto((uint8_t *)"hackOnline", 10);

	// Initialize Timeout Ticker
	this->lastHeartbeat = time(NULL);
}

Client::~Client()
{
	// Free RX Buffer
	delete[] this->rxBuffer;

	// Free Cryptography Memory
	for(uint32_t i = 0; i < 4; i++)
		if(crypto[i] != NULL)
			delete crypto[i];

	// Close Socket
	close(this->socket);
}

int Client::GetSocket()
{
	// Return Socket
	return this->socket;
}

uint8_t * Client::GetRXBuffer(bool addPosition)
{
	// Return Buffer
	return this->rxBuffer + (addPosition ? this->rxBufferPosition : 0);
}

int Client::GetFreeRXBufferSize()
{
	// Return available RX Buffer Size
	return this->rxBufferLength - this->rxBufferPosition;
}

void Client::MoveRXPointer(int delta)
{
	// Incoming Data
	if(delta > 0)
	{
		// Move RX Buffer Pointer
		this->rxBufferPosition += delta;

		// Update Timeout Ticker
		this->lastHeartbeat = time(NULL);

		// Log Event
		printf("Added %d bytes to RX Buffer!\n", delta);
	}

	// Processed Data
	else if(delta < 0)
	{
		// Positive Delta
		delta *= (-1);

		// Move Memory
		memcpy(this->rxBuffer, this->rxBuffer + delta, this->rxBufferLength - delta);

		// Fix Position
		this->rxBufferPosition -= delta;

		// Log Event
		printf("Erased %d bytes from RX Buffer\n", delta);
	}
}

bool Client::ProcessRXBuffer()
{
	// Data available in RX Buffer
	while(this->rxBufferPosition > 2)
	{
		// Extract Packet Length
		uint16_t packetLength = ntohs(*(uint16_t *)this->rxBuffer);

		// Packet available in RX Buffer
		if(this->rxBufferPosition >= (int)(sizeof(uint16_t) + packetLength))
		{
			// Extract Packet Opcode
			uint16_t packetOpcode = ntohs(*(uint16_t *)(this->rxBuffer + sizeof(uint16_t)));

			// Create Crypto Input Pointer
			uint8_t * encryptedPacket = this->rxBuffer + 2 * sizeof(uint16_t);

			// Substract Opcode Field from Packet Length
			packetLength -= sizeof(uint16_t);

			// Output Packet Opcode
			printf("Packet Opcode: 0x%02X\n", packetOpcode);

			// Packet has a body
			if(packetLength > 0)
			{
				// Output Encrypted Data
				printf("Encrypted Data: ");
				for(int i = 0; i < packetLength; i++)
				{
					printf("0x%02X", encryptedPacket[i]);
					if(i != packetLength - 1) printf(", ");
				}
				printf("\n");

				// Decrypt Data
				uint8_t decryptedPacket[0x40C];
				uint32_t decryptedPacketLength = sizeof(decryptedPacket);
				Crypto * packetCrypto = NULL;
				switch (packetOpcode)
				{
					case OPCODE_LOGIN:
						// Key Exchange Request Key
						packetCrypto = crypto[1];
						break;
					default:
						// "hackOnline" Key
						packetCrypto = crypto[0];
				}
				packetCrypto->Decrypt(encryptedPacket, packetLength, decryptedPacket, &decryptedPacketLength);

				// Accumulate Block Header Lengths to generate alternative Packet Length
				uint32_t realDecryptedPacketLength = sizeof(uint16_t);
				while((realDecryptedPacketLength + sizeof(uint16_t)) <= decryptedPacketLength)
				{
					// Read Block Length
					uint16_t blockLength = ntohs(*(uint16_t *)(decryptedPacket + realDecryptedPacketLength));

					// Block seems available
					if(blockLength > 0 && (realDecryptedPacketLength + sizeof(uint16_t) + blockLength) <= decryptedPacketLength)
					{
						// Accumulate Size
						realDecryptedPacketLength += sizeof(uint16_t) + blockLength;
					}

					// End of Packet
					else break;
				}

				// Output Decrypted Data
				printf("Decrypted Data: ");
				for(uint32_t i = 0; i < decryptedPacketLength; i++)
				{
					printf("0x%02X", decryptedPacket[i]);
					if(i != decryptedPacketLength - 1) printf(", ");
				}
				printf("\n");

				// Invalid Packet Length (body is never < 3)
				if(decryptedPacketLength < 3)
				{
					printf("Received packet with an invalid body length of %u bytes!\n", decryptedPacketLength);
					return false;
				}

				// Read Packet Checksum
				uint16_t packetChecksum = ntohs(*(uint16_t *)decryptedPacket);

				// Calculate Checksum
				uint16_t calculatedPacketChecksum = packetCrypto->Checksum(decryptedPacket + sizeof(uint16_t), decryptedPacketLength - sizeof(uint16_t));

				// Invalid Packet Checksum
				if(packetChecksum != calculatedPacketChecksum)
				{
					// Attempt Calculating Checksum without Blowfish Trailing Garbage
					calculatedPacketChecksum = packetCrypto->Checksum(decryptedPacket + sizeof(uint16_t), realDecryptedPacketLength - sizeof(uint16_t));

					// Packet Checksum still invalid
					if(packetChecksum != calculatedPacketChecksum)
					{
						printf("Received packet failed the checksum test (0x%02X != 0x%02X)!\n", packetChecksum, calculatedPacketChecksum);
						return false;
					}
				}

				// Use Block Header Length Data from here on out
				decryptedPacketLength = realDecryptedPacketLength;

				// Packet Switch
				switch(packetOpcode)
				{
					// Prevent Hacking Attempts
					case OPCODE_PING:
					printf("0x%02X packets shouldn't have a body!\n", packetOpcode);
					return false;

					// Key Exchange Request
					case OPCODE_KEY_EXCHANGE_REQUEST:
					{
						// Read Key Length from Packet
						uint16_t keyLength = ntohs(*(uint16_t *)(decryptedPacket + sizeof(uint16_t)));
						
						// Read Key from Packet
						uint8_t * key = decryptedPacket + sizeof(uint16_t) * 2;
						
						// Key Length out of bounds
						if(keyLength == 0 || keyLength > decryptedPacketLength - (sizeof(uint16_t) * 2))
						{
							printf("Received key length (%u > %u) exceeds the packet boundaries!\n", keyLength, decryptedPacketLength - sizeof(uint16_t) * 2);
							return false;
						}
						
						// Key Length over maximum allowed length
						if(keyLength > 16)
						{
							printf("Received key length exceeds the allowed maximum key length (%u > 16)\n", keyLength);
							return false;
						}
						
						// Create Cryptography Objects
						crypto[1] = new Crypto(key, keyLength);
						uint8_t randKey[16];
						for(uint32_t i = 0; i < sizeof(randKey); i++) randKey[i] = rand() % 256;
						crypto[2] = new Crypto(randKey, sizeof(randKey));
						
						// Allocate Response Buffer
						uint8_t response[52];
						uint8_t decryptedResponse[48];
						
						// Cast Fields
						uint16_t * packetLengthField = (uint16_t *)response;
						uint16_t * packetOpcodeField = &packetLengthField[1];
						uint8_t * packetPayloadField = (uint8_t *)&packetOpcodeField[1];
						uint16_t * checksumField = (uint16_t *)decryptedResponse;
						uint16_t * keyLengthField1 = &checksumField[1];
						uint8_t * keyField1 = (uint8_t *)&keyLengthField1[1];
						uint16_t * keyLengthField2 = (uint16_t *)(keyField1 + keyLength);
						uint8_t * keyField2 = (uint8_t *)&keyLengthField2[1];
						
						// Write Static Data
						*packetLengthField = htons(sizeof(response) - sizeof(*packetLengthField));
						*packetOpcodeField = htons(OPCODE_KEY_EXCHANGE_RESPONSE);
						*keyLengthField1 = htons(keyLength);
						*keyLengthField2 = htons(sizeof(randKey));
						
						// Write Secret Keys
						memcpy(keyField1, key, keyLength);
						memcpy(keyField2, randKey, sizeof(randKey));
						
						// Calculate Checksum
						*checksumField = htons(packetCrypto->Checksum((uint8_t *)&checksumField[1], sizeof(decryptedResponse) - sizeof(*checksumField)));
						
						// Encrypt Response
						uint32_t packetPayloadFieldSize = sizeof(response) - sizeof(*packetLengthField) - sizeof(*packetOpcodeField);
						packetCrypto->Encrypt(decryptedResponse, sizeof(decryptedResponse), packetPayloadField, &packetPayloadFieldSize);
						
						// Send Response
						send(socket, response, sizeof(response), 0);

						// Log Event
						printf("Key Exchange finished!\n");

						// Break Switch
						break;
					}

					// Network Key Change Request
					case OPCODE_SET_NETWORK_KEY:
					{
						// Read Key Length from Packet
						uint16_t keyLength = ntohs(*(uint16_t *)(decryptedPacket + sizeof(uint16_t)));

						// Read Key from Packet
						uint8_t * key = decryptedPacket + sizeof(uint16_t) * 2;

						// Key Length out of bounds
						if(keyLength == 0 || keyLength > decryptedPacketLength - (sizeof(uint16_t) * 2))
						{
								printf("Received key length (%u > %u) exceeds the packet boundaries!\n", keyLength, decryptedPacketLength - sizeof(uint16_t) * 2);
								return false;
						}

						// Key Length over maximum allowed length
						if(keyLength > 16)
						{
								printf("Received key length exceeds the allowed maximum key length (%u > 16)\n", keyLength);
								return false;
						}

						// Create Cryptography Object
						crypto[3] = new Crypto(key, keyLength);

						// Debug Output
						printf("Network Key has been changed!\n");

						// Break Switch
						break;
					}

					// Login Request
					case OPCODE_LOGIN:
					{
						// Log Event
						printf("Received Login Packet!\n");

						uint8_t testbuffer[32];
						uint32_t testbufferlen = sizeof(testbuffer) / 2;
						crypto[1]->Decrypt(decryptedPacket + 4, 16, testbuffer + 16, &testbufferlen);
						crypto[2]->Decrypt(testbuffer + 16, 16, testbuffer, &testbufferlen);
						for(uint32_t i = 0; i < testbufferlen; i++)
						{
							printf("0x%02X", testbuffer[i]);
							if(i != testbufferlen - 1) printf(", ");
						}
						printf("\n");

						// Break Switch
						break;
					}

					// Unknown Packet Opcode
					default:
					printf("Unknown packet opcode 0x%02X!\n", packetOpcode);
					return false;
				}
			}

			// Packet has no body
			else
			{
				// Packet Switch
				switch(packetOpcode)
				{
					// Prevent Hacking Attempts
					case OPCODE_KEY_EXCHANGE_REQUEST:
					printf("0x%02X packets need a body!\n", packetOpcode);
					return false;

					// Ping Packet
					case OPCODE_PING:
					printf("Received Ping!\n");
					this->lastHeartbeat = time(NULL);
					break;

					// Unknown Packet Opcode
					default:
					printf("Unknown packet opcode 0x%02X!\n", packetOpcode);
					return false;
				}
			}

			// Discard Data
			MoveRXPointer((sizeof(uint16_t) * 2 + packetLength) * (-1));
		}

		// Not enough Data available
		else break;
	}

	// Keep Connection alive
	return true;
}

bool Client::IsTimedOut()
{
	// Calculate Delta Time
	double deltaTime = difftime(time(NULL), this->lastHeartbeat);

	// No Reaction in 30s
	return deltaTime >= 30;
}

