#ifndef _CLIENT_H_
#define _CLIENT_H_

#include <stdint.h>
#include <time.h>
#include "crypto.h"
#include <iostream>
#include <fstream>


#define KEY_CLIENT 0
#define KEY_SERVER 1
#define KEY_CLIENT_PENDING 2
#define KEY_SERVER_PENDING 3



typedef std::ofstream clOfstream;

class Client
{
	private:

	// Socket
	int socket;
	int segServer;
	int segClient;
	uint32_t opBuster;
	uint16_t lastOp;
	

	bool hasSentSwitch;
	bool hasFirstServSeg;
	bool enableLogging;

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

	clOfstream logFile;
	
	//I guess we'll go with with the defines, CLIENTTYPE_GAME and CLIENTTYPE_AREASERVER...
	uint16_t clientType;

	// Return RX Buffer Reference
	uint8_t * GetRXBuffer(bool addPosition);

	// Return available RX Buffer Size
	int GetFreeRXBufferSize();


	
	//sendPacket0x30
	bool sendPacket30(uint8_t * args, uint32_t aSize, uint16_t opcode);

    //sendPacket0x30_2, sends with an argSize different from the actual amount of data. why? because I'm seeing some weird stuff in the packets.
	bool sendPacket30_2(uint8_t * args, uint32_t aSize, uint16_t opcode, uint16_t aSize2);

            
    // sendPacket
    bool sendPacket(uint8_t * packet, uint32_t packetSize, uint32_t opcode);

	uint32_t getServerSegment();

	// Move RX Buffer Pointer
	void MoveRXPointer(int delta);

	void processPacket30(uint8_t * args, uint16_t aSize, uint16_t opcode);

	// Process RX Buffer Content
	bool ProcessRXBuffer();

	// Return Client Timeout Status
	bool IsTimedOut();
};

#endif