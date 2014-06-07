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

	// Logfile Stream
	clOfstream logFile;
	
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

	// Client Type (CLIENTTYPE_GAME for PS2 or CLIENTTYPE_AREASERVER for PC)
	uint16_t clientType;

	// .hack//frägment DNAS Disc ID (dummied pretty much)
	char diskID[65];

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

	// 3D Model of the currently selected Character (inside of Lobby)
	uint32_t activeCharacterModel;

	// Maximum HP of the currently selected Character (inside of Lobby)
	uint16_t activeCharacterHP;

	// Maximum SP of the currently selected Character (inside of Lobby)
	uint16_t activeCharacterSP;

	// Current GP of the currently selected Character (inside of Lobby)
	uint32_t activeCharacterGP;

	// Number of God Statues visited offline with the currently selected Character (inside of Lobby)
	uint16_t activeCharacterOfflineGodCounter;

	// Number of God Statues visited online with the currently selected Character (inside of Lobby)
	uint16_t activeCharacterOnlineGodCounter;

	/**
	 * Internal Common Constructor
	 * @param socket Socket
	 */
	void CommonConstructor(int socket);

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

	public:

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
	 * Returns the Client Type
	 * @return Client Type (or -1 if undefined)
	 */
	int GetClientType();

	/**
	 * Returns the Disk ID of the Client (as a 64B null terminated hexstring)
	 * @return Disk ID (or NULL if undefined)
	 */
	const char * GetDiskID();

	/**
	 * Returns the Disk ID of the Client (as a 32B array)
	 * @return Disk ID (or NULL if undefined)
	 */
	const uint8_t * GetDiskIDBytes();

	/**
	 * Returns the System Save ID of the Client (as a 64B null terminated hexstring)
	 * @return System Save ID (or NULL if undefined)
	 */
	const char * GetSaveID();

	/**
	 * Returns the System Save ID of the Client (as a 32B array)
	 * @return System Save ID (or NULL if undefined)
	 */
	const uint8_t * GetSaveIDBytes();

	/**
	 * Returns the Character Save ID of the Client (as a 64B null terminated hexstring)
	 * @return Character Save ID (or NULL if undefined)
	 */
	const char * GetCharacterSaveID();

	/**
	 * Returns the Character Save ID of the Client (as a 32B array)
	 * @return Character Save ID (or NULL if undefined)
	 */
	const uint8_t * GetCharacterSaveIDBytes();

	/**
	 * Returns the Name of the logged in Character (inside of Lobby)
	 * @return Character Name (or NULL if undetectable)
	 */
	const char * GetCharacterName();

	/**
	 * Returns the Greeting Message of the logged in Character (inside of Lobby)
	 * @return Character Greeting (or NULL if undetectable)
	 */
	const char * GetCharacterGreeting();

	/**
	 * Returns the Level of the logged in Character (inside of Lobby)
	 * @return Character Level (or -1 if undetectable)
	 */
	int GetCharacterLevel();

	/**
	 * Returns the numeric Class of the logged in Character (inside of Lobby)
	 * @return Numeric Character Class (or -1 if undetectable)
	 */
	int GetCharacterClass();

	/**
	 * Returns a human-readable Class Name of the logged in Character (inside of Lobby)
	 * @return Character Class Name (or NULL if undetectable)
	 */
	const char * GetCharacterClassName();

	/**
	 * Returns the Model Class of the logged in Character (inside of Lobby)
	 * @return Model Class (or -1 if undetectable)
	 */
	char GetCharacterModelClass();

	/**
	 * Returns the Model Number of the logged in Character (inside of Lobby)
	 * @return Model Number (or -1 if undetectable)
	 */
	char GetCharacterModelNumber();

	/**
	 * Returns the Model Type of the logged in Character (inside of Lobby)
	 * @return Model Type (or -1 if undetectable)
	 */
	char GetCharacterModelType();

	/**
	 * Returns the Color Code of the logged in Character (inside of Lobby)
	 * @return Character Color Code (or NULL if undetectable)
	 */
	const char * GetCharacterModelColorCode();

	/**
	 * Returns the Character Portrait of the logged in Character (inside of Lobby)
	 * @param rounded Return the rounded portrait?
	 * @return Character Portrait (or NULL if undetectable)
	 */
	const char * GetCharacterModelPortrait(bool rounded);

	/**
	 * Returns the Height of the logged in Character (inside of Lobby)
	 * @return Character Height (or -1 if undetectable)
	 */
	int GetCharacterModelHeight();

	/**
	 * Returns the Weight of the logged in Character (inside of Lobby)
	 * @return Character Weight (or -1 if undetectable)
	 */
	int GetCharacterModelWeight();

	/**
	 * Returns the HP of the logged in Character (inside of Lobby)
	 * @return Character HP (or -1 if undetectable)
	 */
	int GetCharacterHP();

	/**
	 * Returns the SP of the logged in Character (inside of Lobby)
	 * @return Character SP (or -1 if undetectable)
	 */
	int GetCharacterSP();

	/**
	 * Returns the GP of the logged in Character (inside of Lobby)
	 * @return Character GP (or -1 if undetectable)
	 */
	int64_t GetCharacterGP();

	/**
	 * Returns the number of Offline / Online Dungeons the logged in Character finished (inside of Lobby)
	 * @param online Should the Online Counter be returned?
	 * @return Offline Dungeon Counter (or -1 if undetectable)
	 */
	int GetGodStatueCounter(bool online);

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
	 * Read Client Timeout Status
	 * @return Timeout Status
	 */
	bool IsTimedOut();
};

#endif
