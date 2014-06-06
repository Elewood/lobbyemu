#ifndef _CLIENT_H_
#define _CLIENT_H_

#include <stdint.h>
#include <time.h>
#include "crypto.h"
#include <iostream>
#include <fstream>
#include "areaServer.h"

// Cryptography Key Array Indices
#define KEY_CLIENT 0
#define KEY_SERVER 1
#define KEY_CLIENT_PENDING 2
#define KEY_SERVER_PENDING 3

#define MIN_CHARACTER_LEVEL 1
#define MAX_CHARACTER_LEVEL 99

#define CLASS_TWINBLADE 0
#define CLASS_BLADEMASTER 1
#define CLASS_HEAVYBLADE 2
#define CLASS_HEAVYAXE 3
#define CLASS_LONGARM 4
#define CLASS_WAVEMASTER 5

// Message of the Day
extern const char * MOTD;

// Logfile Stream Type Definition
typedef std::ofstream clOfstream;

class Client
{
	private:

	// Socket
	int socket;

	// Server Segment Number
	uint32_t segServer;

	// Client Segment Number
	uint32_t segClient;

	// Area Server Object
	AreaServer * aServ; // set when it becomes obvious Client is an Area Server	

	// Area Server Local IP Address (LAN)
	uint32_t asLocalAddr; // acquired through packet contents

	// Area Server Public IP Address (WAN)
	uint32_t asExtAddr; // acquired through Socket Context

	// Area Server Port
	uint16_t asPort; // acquired through Socket Context
	
	// Network Logging Bit
	bool enableLogging;

	// Cryptography Handler
	Crypto * crypto[4];

	// RX Buffer Length
	uint32_t rxBufferLength;

	// RX Buffer Pointer
	uint32_t rxBufferPosition;

	// RX Buffer
	uint8_t * rxBuffer;

	// Timeout Timer
	time_t lastHeartbeat;

	/**
	 * Internal Common Constructor
	 * @param socket Socket
	 */
	void CommonConstructor(int socket);

	public:

	// Client Type (CLIENTTYPE_GAME for PS2 or CLIENTTYPE_AREASERVER for PC)
	uint16_t clientType;

	// .hack//frägment DNAS Disc ID (dummied pretty much)
	char diskID[64];

	// .hack//frägment System Save ID
	char saveID[21];

	// .hack//frägment Character Save ID
	char activeCharacterSaveID[21];

	// Currently selected Character (inside of Lobby)
	char activeCharacter[64];

	// Greeting Message of the currently selected Character (inside of Lobby)
	char activeCharacterGreeting[256];

	// Class of the currently selected Character (inside of Lobby)
	uint8_t activeCharacterClass;

	// Level of the currently selected Character (inside of Lobby)
	uint16_t activeCharacterLevel;

	// Logfile Stream
	clOfstream logFile;
	
	/**
	 * Creates a Crypto-Client Network Channel
	 * @param socket Socket
	 */
	Client(int socket);

	/**
	 * Create a Crypto-Client Network Channel
	 * @param socket Socket
	 * @param extIp Public IP Address (AreaServer)
	 */
	Client(int socket, uint32_t extIp);

	/**
	 * Destructor
	 */
	~Client();

	/**
	 * Returns the Client Network Socket
	 * @return Socket
	 */
	int GetSocket();

	/**
	 * Returns the next available RX Buffer Pointer
	 * @param addPosition Considers used RX Buffer Segments in Pointer Calculation if set to true
	 * @return RX Buffer Pointer
	 */
	uint8_t * GetRXBuffer(bool addPosition);

	/**
	 * Returns available RX Buffer Size (in Bytes)
	 * @return Available RX Buffer Size (in Bytes)
	 */
	int GetFreeRXBufferSize();
	
	/**
	 * Moves the RX Buffer Pointer
	 * @param delta Movement Vector (can be negative)
	 */
	void MoveRXPointer(int delta);

	/**
	 * Process accumulated Packets on the RX Buffer
	 * @return Processing Result
	 */
	bool ProcessRXBuffer();

	/**
	 * 0x30 Data Packet Processor
	 * @param args Argument Buffer
	 * @param aSize Argument Length (in Bytes)
	 * @param opcode Internal Packet Opcode
	 */
	void processPacket30(uint8_t * args, uint16_t aSize, uint16_t opcode);

	/**
	 * Wraps Data into a 0x30 Crypto Packet and sends it
	 * @param args Argument Buffer
	 * @param aSize Argument Buffer Length (in Bytes)
	 * @param opcode Internal Packet Opcode
	 * @return Result
	 */
	bool sendPacket30(uint8_t * args, uint32_t aSize, uint16_t opcode);

	/**
	 * Wraps Data into a Crypto Packet and sends it
	 * @param packet Data Buffer
	 * @param packetSize Data Buffer Length (in Bytes)
	 * @param opcode Packet Opcode
	 * @return Result
	 */
	bool sendPacket(uint8_t * packet, uint32_t packetSize, uint32_t opcode);

	/**
	 * Wraps Data into a HTTP GET Response Packet and sends it
	 * @param buffer HTTP Page Content (usually text)
	 * @param bufferLength HTTP Page Content Length (in Bytes)
	 * @param contentType HTTP Content Mimetype (ex. "text/html")
	 * @return Result
	 */
	bool sendHTTP(char * buffer, uint32_t bufferLength, char * contentType);

	/**
	 * Send the News Category List to the Client
	 * @return Result
	 */
	bool sendNewsCategories();
	
	/**
	 * Send the News Post List for a set Category to the Client
	 * @param category Category ID
	 * @return Result
	 */
	bool sendNewsPostList(uint16_t category);

	/**
	 * Send News Post Content for a set Post to the Client
	 * @param postID Post ID
	 * @return Result
	 */
	bool sendNewsPost(uint16_t postID);
	
	/**
	 * Increases the Server Segment Number and returns the latest available Segment Number for Packet Use
	 * @return Next available Server Segment Number
	 */
	uint32_t getServerSegment();

	/**
	 * Read Client Timeout Status
	 * @return Timeout Status
	 */
	bool IsTimedOut();
};

#endif
