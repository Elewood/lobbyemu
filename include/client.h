#ifndef _CLIENT_H_
#define _CLIENT_H_

#include <stdint.h>
#include <time.h>
#include "crypto.h"

#define KEY_CLIENT 0
#define KEY_SERVER 1
#define KEY_CLIENT_PENDING 2
#define KEY_SERVER_PENDING 3

class Client
{
	private:

	// Socket
	int socket;

	// Cryptography Handler
	Crypto * crypto[4];

	// RX Buffer Length
	int rxBufferLength;

	// RX Buffer Pointer
	int rxBufferPosition;

	// RX Buffer
	uint8_t * rxBuffer;

	// Timeout Timer
	time_t lastHeartbeat;

	public:

	// Constructor
	Client(int socket);

	// Destructor
	~Client();

	// Return Socket
	int GetSocket();

	// Return RX Buffer Reference
	uint8_t * GetRXBuffer(bool addPosition);

	// Return available RX Buffer Size
	int GetFreeRXBufferSize();

	// Move RX Buffer Pointer
	void MoveRXPointer(int delta);

	// Process RX Buffer Content
	bool ProcessRXBuffer();

	// Return Client Timeout Status
	bool IsTimedOut();
};

#endif

