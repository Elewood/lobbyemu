#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include "client.h"

Client::Client(int socket)
{
	// Save Socket
	this->socket = socket;

	// Initialize RX Buffer
	this->rxBufferPosition = 0;
	this->rxBufferLength = 2048;
	this->rxBuffer = new uint8_t[this->rxBufferLength];

	// Create Cryptography Handler
	crypto = new Crypto((uint8_t *)"hackOnline", 10);

	// Initialize Timeout Ticker
	this->lastHeartbeat = time(NULL);
}

Client::~Client()
{
	// Free RX Buffer
	delete[] this->rxBuffer;

	// Free Cryptography Memory
	delete crypto;

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

			// Substract Packet Length Field from Packet Length
			packetLength -= sizeof(uint16_t);

			// Output Packet Opcode
			printf("Packet Opcode: 0x%02X\n", packetOpcode);

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
			crypto->Decrypt(encryptedPacket, packetLength, decryptedPacket, &decryptedPacketLength);

			// Output Decrypted Data
			printf("Decrypted Data: ");
			for(uint32_t i = 0; i < decryptedPacketLength; i++)
			{
				printf("0x%02X", decryptedPacket[i]);
				if(i != decryptedPacketLength - 1) printf(", ");
			}
			printf("\n");

			// Discard Data
			MoveRXPointer((sizeof(uint16_t) + packetLength) * (-1));
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

