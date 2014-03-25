#ifndef _CLIENT_H_
#define _CLIENT_H_

#include <stdint.h>
#include <time.h>
#include "crypto.h"
#include <iostream>
#include <fstream>
#include "areaServer.h"

#define KEY_CLIENT 0
#define KEY_SERVER 1
#define KEY_CLIENT_PENDING 2
#define KEY_SERVER_PENDING 3

extern const char * MOTD;

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

	AreaServer * aServ;	

	//this is mainly used for Clients that turn out to be Area Servers.
	uint32_t asLocalAddr; //local address comes in off the packets
	uint32_t asExtAddr;   //we get this when we accept the connection
	uint16_t asPort;	  //this comes in with the local address.
	


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

	Client(int socket, uint32_t extIp);

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

	                                                
    // sendPacket
    bool sendPacket(uint8_t * packet, uint32_t packetSize, uint32_t opcode);

	
	//DBDRIVEN: sends news categories when requested.
	bool sendNewsCategories();
	
	//DBDRIVEN: sends newsPosts for a specific category
	bool sendNewsPostList(uint16_t category);
	//DBDRIVEN: sends a specific news post.
	bool sendNewsPost(uint16_t postID);
	
	
	//sends Lobby Categories when requested.
	bool sendLobbyCategories();
	
	//DBDRIVEN:  sends lobby list for specific category
	bool sendLobbyList(uint16_t category);
	
	
	//DBDRIVEN: sends BBS category list when requested.
	bool sendBBSCategories();	
	
	//DBDRIVEN: sends BBS post list for specific category.
	bool sendBBSPostList(uint16_t category);
	
	//DBDRIVEN: sends BBS thread list
	bool sendBBSThreadList(uint16_t threadID);
	
	//DBDRIVEN: sends BBS post
	bool sendsBBSPost(uint16_t postId);
	
	//DBDRIVEN: processes a post to the BBS and posts, if possible.
	bool postToBBS(uint8_t * args, uint16_t aSize);

	
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