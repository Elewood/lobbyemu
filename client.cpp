#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>
#include "opcode.h"
#include "client.h"
#include "server.h"
#include <ctime>
#include "areaServer.h"
#include <list>
#include "ccsNewsImage.h"

// Class Names
char * classNames[CLASS_WAVEMASTER + 1] = {
	(char *)"Twin Blade",
	(char *)"Blademaster",
	(char *)"Heavy Blade",
	(char *)"Heavy Axe",
	(char *)"Long Arm",
	(char *)"Wavemaster"
};

/**
 * Creates a Crypto-Client Network Channel
 * @param socket Socket
 */
Client::Client(int socket)
{
	// Forward Call
	CommonConstructor(socket);
}

/**
 * Create a Crypto-Client Network Channel
 * @param socket Socket
 * @param extIp Public IP Address (AreaServer)
 */
Client::Client(int socket, uint32_t extIp)
{
	// Save Area Server IP
	this->asExtAddr = extIp;

	// Forward Call
	CommonConstructor(socket);
}

/**
 * Internal Common Constructor
 * @param socket Socket
 */
void Client::CommonConstructor(int socket)
{
	// Save Socket
	this->socket = socket;

	// Set Client Type to undefined state
	this->clientType = 0;

	// Initialize Area Server Field
	this->aServ = NULL;

	// Initialize Game Data Fields
	memset(this->diskID, 0, sizeof(this->diskID));
	memset(this->saveID, 0, sizeof(this->saveID));
	memset(this->activeCharacterSaveID, 0, sizeof(this->activeCharacterSaveID));
	memset(this->activeCharacter, 0, sizeof(this->activeCharacter));
	memset(this->activeCharacterGreeting, 0, sizeof(this->activeCharacterGreeting));

	// Initialize RX Buffer
	this->rxBufferPosition = 0;
	this->rxBufferLength = 2048;
	this->rxBuffer = new uint8_t[this->rxBufferLength];

	// Create Cryptography Objects
	for(uint32_t i = 0; i < 2; i++)
		crypto[i] = new Crypto((uint8_t *)"hackOnline", 10);
	for(uint32_t i = 2; i < 4; i++)
		crypto[i] = NULL;

	// Initialize Timeout Ticker
	this->lastHeartbeat = time(NULL);

	// Set Starting Segment Numbers
	this->segServer = 0x0e;
	this->segClient = 0;

	// Enable Logging (for now)
	this->enableLogging = true;
	
	// Prepare Logging File
	if(this->enableLogging)
	{
		// Craft Filename
		time_t curTime;
		struct tm * timeinfo;
		char buffer[256];
		char logFileName[256];
		char cwrd[256];
		getcwd(cwrd, sizeof(cwrd));
		time(&curTime);
		timeinfo = localtime(&curTime);
		strftime(buffer, 256,"%d-%m-%y_%I-%M-%S", timeinfo);
		sprintf(logFileName, "%s/logs/%s.txt", cwrd, buffer);

		// Notifying Administrator
		printf("Opening Log for writing: %s\n", logFileName);

		// Opening File
		this->logFile.open(logFileName, std::ios::app);
	}
}

/**
 * Destructor
 */
Client::~Client()
{
	// Client was an Area Server
	if (this->aServ != NULL)
	{
		// Remove Area Server from Server List
		Server::getInstance()->GetAreaServerList()->remove(this->aServ);

		// Delete Area Server Object
		delete this->aServ;

		// Notify Administrator
		printf("REMOVED AREA SERVER FROM LIST!\n");
	}

	// Free RX Buffer
	delete[] this->rxBuffer;

	// Free Cryptography Memory
	for(uint32_t i = 0; i < 4; i++)
		if(crypto[i] != NULL)
			delete crypto[i];

	// Close Socket
	close(this->socket);
	this->logFile.close();
}

/**
 * Returns the Client Network Socket
 * @return Socket
 */
int Client::GetSocket()
{
	// Return Socket
	return this->socket;
}

/**
 * Returns the next available RX Buffer Pointer
 * @param addPosition Considers used RX Buffer Segments in Pointer Calculation if set to true
 * @return RX Buffer Pointer
 */
uint8_t * Client::GetRXBuffer(bool addPosition)
{
	// Return Buffer
	return this->rxBuffer + (addPosition ? this->rxBufferPosition : 0);
}

/**
 * Returns available RX Buffer Size (in Bytes)
 * @return Available RX Buffer Size (in Bytes)
 */
int Client::GetFreeRXBufferSize()
{
	// Return available RX Buffer Size
	return this->rxBufferLength - this->rxBufferPosition;
}

/**
 * Moves the RX Buffer Pointer
 * @param delta Movement Vector (can be negative)
 */
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
		memmove(this->rxBuffer, this->rxBuffer + delta, this->rxBufferLength - delta);

		// Fix Position
		this->rxBufferPosition -= delta;

		// Log Event
		printf("Erased %d bytes from RX Buffer\n", delta);
	}
}

/**
 * Increases the Server Segment Number and returns the latest available Segment Number for Packet Use
 * @return Next available Server Segment Number
 */
uint32_t Client::getServerSegment()
{
	// Increment Server Segment Number
	this->segServer += 1;

	// Return next available Server Segment Number
	return this->segServer - 1;
}

/**
 * Wraps Data into a 0x30 Crypto Packet and sends it
 * @param args Argument Buffer
 * @param aSize Argument Buffer Length (in Bytes)
 * @param opcode Internal Packet Opcode
 * @return Result
 */
bool Client::sendPacket30(uint8_t * args, uint32_t aSize, uint16_t opcode)
{
	// Result
	bool result = false;

	// Calculate real decrypted Data Length (segCount + DataSize + subOpCode + aSize)
	uint32_t dataLen = sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t) + aSize;

	// Calculate Blowfish-aligned decrypted Data Length (checksum + real decrypted data length + Blowfish-Round padding)
	uint32_t decryptedResponseLen = sizeof(uint16_t) + dataLen;
	if(decryptedResponseLen % 8 > 0)
	{
		decryptedResponseLen = decryptedResponseLen / 8;
		decryptedResponseLen = (decryptedResponseLen + 1) * 8;
	}
	
	// Calculate Response Length (packet length + packet opcode + Blowfish-aligned decrypted Data Length)
	uint32_t responseLen = decryptedResponseLen + (sizeof(uint16_t) * 2);

	// Allocate Working Buffers
	uint8_t * response = new uint8_t[responseLen];
	uint8_t * decryptedResponse = new uint8_t[decryptedResponseLen];

	// Clear Blowfish Working Buffer
	memset(decryptedResponse, 0, decryptedResponseLen);
	
	// Cast Fields for Encrypted Response
	uint16_t * packetLengthField = (uint16_t *)response;
	uint16_t * packetOpcodeField = &packetLengthField[1];
	uint8_t * packetPayloadField = (uint8_t *)&packetOpcodeField[1];
	
	// Cast Fields for Plaintext Payload
	uint16_t * checksumField = (uint16_t *)decryptedResponse;
	uint32_t * segmentField = (uint32_t *)&checksumField[1];
	uint16_t * lengthField = (uint16_t *)&segmentField[1];
	uint16_t * subOpcodeField = &lengthField[1];
	uint8_t * packetField = (uint8_t *)&subOpcodeField[1];
	
	// Write Static Data to outermost Packet Layer (Packet Length & Opcode)
	*packetLengthField = htons(responseLen - sizeof(*packetLengthField));
	*packetOpcodeField = htons(0x30);
	
	// Write Static Data to innermost Plaintext Packet Layer (Segment Number, Argument Length + Checksum Length, Internal Opcode)
	*segmentField = htonl(this->getServerSegment());
	*lengthField = htons(aSize + sizeof(uint16_t));
	*subOpcodeField = htons(opcode);
	
	// Copy Argument Data into innermost Plaintext Packet Layer
	memcpy(packetField, args, aSize);
	
	// Calculate Checksum and store it in Packet
	*checksumField = htons(Crypto::Checksum((uint8_t *)&checksumField[1], dataLen));

	// Notify Administrator
	printf("Generated Packet with Checksum: \n");
	for(uint32_t i = 0; i < decryptedResponseLen; i++)
	{
		printf("0x%02X",decryptedResponse[i]);
		if(i != decryptedResponseLen - 1)
		{
			printf(",");
		}
	}
	printf("\n");

	// Encrypt Packet
	crypto[KEY_SERVER]->Encrypt(decryptedResponse, decryptedResponseLen, packetPayloadField, &decryptedResponseLen);
	
	// Notify Administrator
	/*
	printf("Encrypted Packet:\n");
	for(int i = 0; i < responseLen; i++)
	{
		printf("0x%02X",response[i]);
		if(i < responseLen - 1)
		{
			printf(",");
		}
	}
	printf("\n");
	*/

	// Send Packet
	result = (send(this->socket, (char*)response, responseLen, MSG_NOSIGNAL) == (int)responseLen);

	// Free Memory
	delete [] response;
	delete [] decryptedResponse;

	// Return Result
	return result;
}

/**
 * Wraps Data into a Crypto Packet and sends it
 * @param packet Data Buffer
 * @param packetSize Data Buffer Length (in Bytes)
 * @param opcode Packet Opcode
 * @return Result
 */
bool Client::sendPacket(uint8_t * packet, uint32_t packetSize,uint32_t opcode)
{
	// Calculate Blowfish-aligned decrypted Data Length (checksum + packetSize + Blowfish-Round padding)
	uint32_t decryptedResponseLen = packetSize + sizeof(uint16_t);
	if(decryptedResponseLen % 8 > 0)
	{
		decryptedResponseLen = decryptedResponseLen / 8;
		decryptedResponseLen = (decryptedResponseLen + 1) * 8;
	}

	// Calculate Response Length (packet length + packet opcode + Blowfish-aligned decrypted Data Length)
	uint32_t responseLen = decryptedResponseLen + (sizeof(uint16_t) * 2);

	// Allocate Working Buffers
	uint8_t * response = new uint8_t[responseLen];
	uint8_t * decryptedResponse = new uint8_t[decryptedResponseLen];

	// Cast Fields for Encrypted Response
	uint16_t * packetLengthField = (uint16_t *)response;
	uint16_t * packetOpcodeField = &packetLengthField[1];
	uint8_t * packetPayloadField = (uint8_t *)&packetOpcodeField[1];

	// Cast Fields for Plaintext Payload
	uint16_t * checksumField = (uint16_t *)decryptedResponse;
	uint8_t * packetField = (uint8_t *)&checksumField[1];

	// Write Static Data to outermost Packet Layer (Packet Length & Opcode)
	*packetLengthField = htons(responseLen - sizeof(*packetLengthField));
	*packetOpcodeField = htons(opcode);

	// Copy Argument Data into innermost Plaintext Packet Layer
	memcpy(packetField, packet, packetSize);

	// Calculate Checksum and store it in Packet
	*checksumField = htons(Crypto::Checksum(packet,packetSize));

	// Notify Administrator
	printf("Generated Packet With Checksum: \n");
	for(uint32_t i = 0; i < decryptedResponseLen;i++)
	{
		printf("0x%02X",decryptedResponse[i]);
		if(i != decryptedResponseLen - 1)
		{
			printf(",");
		}
	}
	printf("\n");

	// Encrypt Packet
	crypto[KEY_SERVER]->Encrypt(decryptedResponse,decryptedResponseLen,packetPayloadField,&decryptedResponseLen);

	// Notify Administrator
	/*
	printf("Encrypted Packet:\n");
	for(int i = 0; i < responseLen;i++)
	{
		printf("0x%02X",response[i]);
		if(i < responseLen - 1)
		{
			printf(",");
		}
	}
	printf("\n");
	*/

	// Send Packet
	if (send(socket, (char*)response, responseLen, MSG_NOSIGNAL) == (int)responseLen)
	{
		// Send Success
		return true;
	}

	// Send Failure
	return false;
}

/**
 * Send the News Category List to the Client
 * @return Result
 */
bool Client::sendNewsCategories()
{
//	uint8_t uRes[] = {0x00,0x00};
//	sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_NEWS_GETMENU_FAILED);
	
	
	//send 1 category for testing...
	uint8_t uRes[] = {0x00,0x01};
	sendPacket30(uRes, sizeof(uRes),OPCODE_DATA_NEWS_CATEGORYLIST);
	
	uint8_t uRes2[38] = {0};
	uint16_t *cID = (uint16_t*)uRes2;
	char *catName = (char*)&cID[1];

	
	*cID = htons(0x01);	
	snprintf(catName,34,"Test News Category...");
	sendPacket30(uRes2,sizeof(uRes2),OPCODE_DATA_NEWS_ENTRY_CATEGORY);
	
	//THIS CODE IS FOR SQLITE3 STUFF! JUST COMMENTING IT OUT FOR NOW BECAUSE I'M TOO LAZY TO REMOVE IT FOR COMMIT
	/* 
			
	//get number of categories

	uint16_t numRows = 0;
	sqlite3_stmt *statement;
	if(sqlite3_prepare(srvDatabase,"Select Count(*) from news_category;",-1,&statement,0) == SQLITE_OK)
	{
		int result = sqlite3_step(statement);
		if(result == SQLITE_ROW)
		{
			numRows = sqlite3_column_int(statement,0);
		}
		else
		{
			uint8_t uRes[] = {0x00,0x00};
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_NEWS_GETMENU_FAILED);
			return false;
		}
	}
	else
	{
		uint8_t uRes[] = {0x00,0x00};
		sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_NEWS_GETMENU_FAILED);
		return false;
	}	
	sqlite3_finalize(statement);
	if(numRows == 0)
	{
		uint8_t uRes[] = {0x00,0x00};
		sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_NEWS_GETMENU_FAILED);
		return false;
	}
	
	
	
	uint8_t uRes[2];
	
	//cast field cuz I suck at coding...
	uint16_t * nR = (uint16_t *)uRes;
	
	*nR = htons(numRows);

	sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_NEWS_CATEGORYLIST);
	uint8_t uRes2[38] = {0};

	//We're going to truncate the category name to 34 chars, but I like to keep some extra space.
	//cast fields for response...
	uint16_t * cID = (uint16_t *)uRes2;
	char * catName = (char *)&cID[1];

	if(sqlite3_prepare(srvDatabase,"Select id,Name from NEWS_CATEGORY;",-1,&statement,0) == SQLITE_OK)
	{
		int result = 0;
		for(int row = 0; row < numRows; row++)
		{	
			result = sqlite3_step(statement);
			if(result == SQLITE_ROW)
			{
				*cID = htons((uint16_t)sqlite3_column_int(statement,0));
				snprintf(catName,34,"%s",sqlite3_column_text(statement,1));			
				sendPacket30(uRes2,sizeof(uRes2),OPCODE_DATA_NEWS_ENTRY_CATEGORY);
				
			}
			else
			{
				uint8_t uRes[] = {0x00,0x00};
				sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_NEWS_GETMENU_FAILED);
			}
			
		}
	}
	else
	{
		uint8_t uRes[] = {0x00,0x00};
		sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_NEWS_GETMENU_FAILED);
	}
	sqlite3_finalize(statement);
	*/

	return true;
}

/**
 * Send the News Post List for a set Category to the Client
 * @param category Category ID
 * @return Result
 */
bool Client::sendNewsPostList(uint16_t category)
{
	
	
//	uint8_t uRes[] = {0x00,0x00};
//	sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_NEWS_GETMENU_FAILED);

	//send one test post...
	uint8_t uRes[] = {0x00,0x01};
	sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_NEWS_ARTICLELIST);
	
	uint8_t uRes2[56] = {0};
	uint16_t *pID = (uint16_t*)uRes2;
	char *postName = (char *)&pID[1];
	uint32_t *date = (uint32_t*)&postName[18];
	
	
	
	*pID = htons(0x01);
	snprintf(postName,34,"Test News Post...");
	*date = 0x5367417c;
	sendPacket30(uRes2,sizeof(uRes2),OPCODE_DATA_NEWS_ENTRY_ARTICLE);


	//THIS CODE IS FOR SQLITE3 STUFF! JUST COMMENTING IT OUT FOR NOW BECAUSE I'M TOO LAZY TO REMOVE IT FOR COMMIT
	/* 
	//get number of categories
	uint16_t numRows = 0;
	sqlite3_stmt *statement;
	char tehQ[256];
	
	sprintf(tehQ,"Select Count(*) from news_posts where category == %d;",category);
	if(sqlite3_prepare(srvDatabase,tehQ,-1,&statement,0) == SQLITE_OK)
	{
		int result = sqlite3_step(statement);
		if(result == SQLITE_ROW)
		{
			numRows = sqlite3_column_int(statement,0);
		}
		else
		{
			uint8_t uRes[] = {0x00,0x00};
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_NEWS_GETMENU_FAILED);
			return false;
		}
	}
	else
	{
		uint8_t uRes[] = {0x00,0x00};
		sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_NEWS_GETMENU_FAILED);
		return false;
	}	
	sqlite3_finalize(statement);
//	sqlite3_stmt *statement;

	if(numRows == 0)
	{
		uint8_t uRes[] = {0x00,0x00};
		sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_NEWS_GETMENU_FAILED);
		return false;
	}
			
				
	uint8_t uRes[2];
	
	//cast field cuz I suck at coding...
	uint16_t * nR = (uint16_t *)uRes;
	
	*nR = htons(numRows);

	sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_NEWS_ARTICLELIST);

	uint8_t uRes2[38] = {0};
	//We're going to truncate the category name to 34 chars, but I like to keep some extra space.
	//cast fields for response...
	uint16_t * cID = (uint16_t *)uRes2;
	char * catName = (char *)&cID[1];

	sprintf(tehQ,"Select id,title from news_posts where category == %d;",category);
	
	if(sqlite3_prepare(srvDatabase,tehQ,-1,&statement,0) == SQLITE_OK)
	{
		int result = 0;
		for(int row = 0; row < numRows; row++)
		{	
			result = sqlite3_step(statement);
			if(result == SQLITE_ROW)
			{
				*cID = htons((uint16_t)sqlite3_column_int(statement,0));
				snprintf(catName,34,"%s",sqlite3_column_text(statement,1));			
				sendPacket30(uRes2,sizeof(uRes2),OPCODE_DATA_NEWS_ENTRY_ARTICLE);
				
			}
			else
			{
				uint8_t uRes[] = {0x00,0x00};
				sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_NEWS_GETMENU_FAILED);
			}
			
		}
	}
	else
	{
		uint8_t uRes[] = {0x00,0x00};
		sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_NEWS_GETMENU_FAILED);
	}
	sqlite3_finalize(statement);

	*/
	return true;	
}

/**
 * Send News Post Content for a set Post to the Client
 * @param postID Post ID
 * @return Result
 */
bool Client::sendNewsPost(uint16_t postID)
{
		printf("sending news post!\n");		
	//	uint8_t uRes[] = {0x00,0x04,0xcc,0xcc, 0x01,0x05, 0x30,0x30,0x30,0x30,0x30,0x30,0x00};
	//	sendPacket30(uRes,sizeof(uRes),0x7855);
	
	
	
	//	sendPacket30(uRes,sizeof(uRes),0x7856);

	
		
			
					
//		uint8_t uRes2[] {0x00,0x04,  0x00, 0x00, 0x4e, 0x43, 0x44, 0x79, 0x73, 0x6f, 0x6e, 0x4f, 0x77, 0x6e, 0x73, 0x59, 0x6f, 0x75, 0x2e, 0x00};
		
		
		sendPacket30(newsImage,sizeof(newsImage),0x7856);
		//uint8_t uRes[] = {0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x00,0x00};
		//sendPacket30(uRes,sizeof(uRes),0x7855);

		//uint8_t uRes3[] = {0x4e,0x43,0x44,0x79,0x73,0x6f,0x6e,0x00};
		//sendPacket30(uRes3,sizeof(uRes3),0x7857);
			
		/*
		0x7855
		//wtf?
		struct
		{
			uint32_t unk;
			uint16_t unk;		
			
			
			
			
		}
		
		0x7856
		image?
		struct
		{
			uint16_t unk		
			uint32_t unk	
		}	
		
		
		0x7857
		Getting News Image Failed
		struct
		{
		}
				
		
		
		
		*/
		return true;
}

/**
 * 0x30 Data Packet Processor
 * @param args Argument Buffer
 * @param aSize Argument Length (in Bytes)
 * @param opcode Internal Packet Opcode
 */
void Client::processPacket30(uint8_t * arg, uint16_t aSize, uint16_t opcode)
{

	switch (opcode) 
	{
						
		case OPCODE_DATA_LOGON:
		{
			printf("PACKET= LOGON\n");
			
			if(aSize == 2)
			{
				this->clientType = ntohs(*(uint16_t*)(arg));
				switch (this->clientType)
				{
					case CLIENTTYPE_GAME:
					{
						printf("GAME CLIENT LOGGING IN!\n");
						break;
					}
					
					case CLIENTTYPE_AREASERVER:
					{
						printf("AREA SERVER LOGGING IN!\n");
						break;
					}	
					
					
					default:
					{
						printf("UNKNOWN CLIENT TYPE LOGGING ON!\n");
						break;
					}
				}
				
				
			}
			else
			{
				printf("UNKNOWN LOGON PARAMETERS!\n");
			}
			
			
			
			uint8_t uRes[] = {0x74,0x32};
			
			if(this->clientType == CLIENTTYPE_GAME)
			{
				sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_LOGON_RESPONSE);
			
			}
			else
			{
				uint8_t uRes2[] = {0xde,0xad};
				sendPacket30(uRes2,2,0x78ac);			
			}
			break;	
		}
			
							
											
		case OPCODE_DATA_LOGON_AS2:
		{
			printf("Recieved DATA_LOGON_AS2\n");
			uint8_t uRes[] = {0x02,0x11};
			printf("sending OK\n");
			sendPacket30(uRes,sizeof(uRes),0x701c);
			break;								
		}				
			
		case 0x02:
		{
			printf("Received DATA_PING\n");
			
			
			break;
		}
			
			
		case OPCODE_DATA_AS_DISKID:
		{
			printf("RECEIVED AREA SERVER DISKID!\n");
			uint8_t uRes[] = {0x00,0x00};
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_AS_DISKID_OK);
			
			
			break;
		}
			
		case OPCODE_DATA_AS_IPPORT:
		{
			printf("RECEIVED AREA IP&PORT!\n");
			uint8_t uRes[] = {0x00,0x00};
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_AS_IPPORT_OK);
			if (aSize >= 6)
			{
				this->asLocalAddr = *(uint32_t *)arg;
				this->asPort = *(uint16_t *)(arg + sizeof(uint32_t));
				printf("EXTIP: %08X, INTIP: %08X, PORT: %04X\n",asExtAddr,asLocalAddr,asPort);
			}
			else
			{
				printf("OPCODE_DATA_AS_IPPORT INCOMPLETE\n");
			}
			
			break;
		}	
			
		case OPCODE_DATA_AS_PUBLISH:
		{
			uint8_t uRes[] = {0x00,0x00};
			printf("RECEIVED AREA SERVER PUBLISH\n");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_AS_PUBLISH_OK);
			break;
		}			

		case OPCODE_DATA_AS_PUBLISH_DETAILS1:
		{
			uint8_t uRes[] = {0x00,0x01};
			printf("RECEIVED AREA SERVER PUBLISH1\n");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_AS_PUBLISH_DETAILS1_OK);

			// Minimum Packet Size with Empty Server Name
			if (aSize >= 81)
			{
				//Maximum Packet Size.
				if(aSize >= 102)
				{
					// Terminate Packet (to prevent overflows), and we'll try anyways.
					arg[aSize - 1] = 0;
				}
					//lets cast some fields to get at our data...
					uint8_t * asDiskID = arg;
					//force terminate the DISKID Field...
					arg[64] = 0x0;
					char * serverName = (char *)&asDiskID[65]; //For shame...
					uint32_t serverNameLen = strlen(serverName);
					//If the string size is too big, terminate the string at the max size.
					if(serverNameLen > MAX_AS_NAME_LEN)
					{
						serverName[0x21] = 0x0;
					}
					uint16_t * serverLevel = (uint16_t *)&serverName[serverNameLen + 1];
					uint16_t * sType = &serverLevel[1];
					uint16_t * sUnk = &sType[1];
					uint8_t * sStatus = (uint8_t*)&sUnk[1];
					uint8_t * serverID = &sStatus[1];
					uint8_t * postServerID = serverID + 8;

					// No Overflow detected
					if (postServerID <= &arg[aSize])
					{
						// Create Area Server Object
						this->aServ = new AreaServer(this->socket,this->asExtAddr,this->asLocalAddr,this->asPort,serverName,serverID,ntohs(*serverLevel),*sStatus,ntohs(*sType));

						//REGISTER AREA SERVER...
						Server::getInstance()->GetAreaServerList()->push_back(this->aServ);
					}

			}
			else
			{
				printf("OPCODE_DATA_AS_PUBLISH_DETAILS1 INCOMPLETE\n");
			}

			break;
			
			/*
				struct asPublishDetails1:
				{
					char diskID[65];
					char * serverName; //this is variable length, but no longer than 21 I believe, including null terminator.
					uint16_t serverLevel;
					uint16_t serverType;	//serverType
					uint16_t sUnk;	//Actually, it's not. I'm not sure what that's for yet.
					uint8_t sStatus;		//serverStatus.
					uint8_t serverID[8];
					//We don't really need to worry about the server type or status. the game know's what's up.
				}						
			*/
		}			
		
		case OPCODE_DATA_AS_PUBLISH_DETAILS2:
		{
			uint8_t uRes[] = {0xde,0xad};
			printf("RECEIVED AREA SERVER PUBLISH2\n");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_AS_PUBLISH_DETAILS2_OK);
			break;
		}			
		
		case OPCODE_DATA_AS_PUBLISH_DETAILS3:
		{
			//uint8_t uRes[] = {0x00,0x00};
			printf("RECEIVED AREA SERVER PUBLISH3\n");

			break;
		}			
														
		case OPCODE_DATA_AS_PUBLISH_DETAILS4:
		{
			/*
			uint16_t unk1;
			char diskid[65];
			uint16_t partyslot; // 1-3
			char servername[]; // variable length, null terminated
			char playername[]; // variable length, null terminated, occassional corruption makes this value useless though
			uint16_t unk3;
			uint8_t unk4; // 0x01?
			uint32_t unk5; // 0x00?
			*/

			//uint8_t uRes[] = {0x00,0x01};
			printf("RECEIVED AREA SERVER PUBLISH4\n");

			break;
		}
		
		case OPCODE_DATA_AS_UPDATE_USERNUM:
		{
			printf("\033[32mRECEIVED AS_UPDATE_USERNUM!\033[0m\n");

			// Overflow Check
			if (aSize >= 4)
			{
				this->aServ->setUsers(ntohs(*(uint16_t*)(arg + sizeof(uint16_t))));
			}
			else
			{
				printf("OPCODE_DATA_AS_UPDATE_USERNUM INCOMPLETE\n");
			}

			break;
		}
		
		case OPCODE_DATA_AS_PUBLISH_DETAILS6:
		{
			//uint8_t uRes[] = {0x00,0x00};
			printf("RECEIVED AREA SERVER PUBLISH6\n");

			break;
		}
		case OPCODE_DATA_AS_UPDATE_STATUS:
		{
			printf("RECEIVED AREA SERVER UPDATE STATUS\n");

			// Minimum Packet Length with empty Server Name
			if (aSize >= 81)
			{
				if(aSize >= 102)
				{
					// Terminate Packet to prevent Overflow and try anyways.
					arg[aSize - 1] = 0;
				}

				uint16_t * unk1 = (uint16_t*)arg;
				uint8_t * asDiskID = (uint8_t*)&unk1[1];
				//force terminate diskID Field
				asDiskID[64] = 0x0;
				uint8_t * serverName = &asDiskID[65]; //For shame...
				uint32_t serverNameLen = strlen((char*)serverName);
				//if the string size is too big, terminate the string at the max size.
				if(serverNameLen > MAX_AS_NAME_LEN)
				{
					serverName[0x21] = 0x0;
				}
				uint16_t * serverLevel = (uint16_t *)&serverName[serverNameLen + 1];
				uint16_t * sType = &serverLevel[1];
				uint8_t * sStatus = (uint8_t*)&sType[1];
				uint8_t * serverID = &sStatus[1];
				uint8_t * postServerID = serverID + 8;

				// Overflow Protection
				if (postServerID <= &arg[aSize])
				{
					printf("Set STATUS: %02X\n",*sStatus);			
					this->aServ->setStatus(*sStatus);
					this->aServ->setType(ntohs(*sType));
					this->aServ->setLevel(ntohs(*serverLevel));
				}
			}
			else
			{
				printf("OPCODE_DATA_AS_UPDATE_STATUS INCOMPLETE\n");
			}

			break;
		}

		case OPCODE_DATA_DISKID:
		{
			// Argument given (everything else has to be a hacking attempt and will be ignored here)
			if (aSize >= 10)
			{
				// Terminate Packet (to prevent possible overflow through hacking attempt)
				arg[aSize - 1] = 0;

				// Cast Arguments
				char * diskID = (char *)arg;
				char * staticText = diskID + strlen(diskID) + 1;

				// Prevent Disk ID Overflow Hack
				if (staticText < (char *)(arg + aSize))
				{
					// Valid Static Text
					if (strcmp(staticText, "dot_hack") == 0)
					{
						// Store Data into Client Object
						strncpy(this->diskID, diskID, sizeof(this->diskID));
					}
				}
			}
			else
			{
				printf("OPCODE_DATA_DISKID INCOMPLETE\n");
			}

			// Send Default Response
			uint8_t uRes[] = {0x78,0x94};
			printf("Sending DISKID_OK\n");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_DISKID_OK);
			
			//sendPacket30(uRes,sizeof(uRes),0x7002);
			//sendPacket30(uRes,sizeof(uRes),0x7003);
			//sendPacket30(uRes,sizeof(uRes),0x7004);
			//sendPacket30(uRes,sizeof(uRes),0x7005);
			//sendPacket30(uRes,sizeof(uRes),0x7006);
			//sendPacket30(uRes,sizeof(uRes),0x7007);
			//sendPacket30(uRes,sizeof(uRes),0x7008);
			
			//for(int i = 0; i < 10; i++)
			//{
				//sendPacket30(uRes,sizeof(uRes),(uint16_t)0x7826 + i);
				
				
				
			//}
			break;
		}
			
			
			
			
			
		
			
		case OPCODE_DATA_SAVEID:
		{
			uint8_t uRes[512];
			memset(uRes, 0, sizeof(uRes));
			strncpy((char *)uRes, MOTD, sizeof(uRes) - 1);
			//printf("SENDING: %s\n",uRes);
			printf("Sending SAVEID_OK\n");
			//sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_SAVEID_OK);	
			sendPacket30(uRes,sizeof(uRes),0x742a);	
		
		
			break;
		}																						
		
		case OPCODE_DATA_COM:
		{
			uint8_t uRes[] = {0xde,0xad};//,0xad};
			//snprintf((char*)uRes,33,"Welcome to .hack//Fragment!");
			printf("Sending COM_OK\n");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_COM_OK);
			
			break;
		}			
		
																			
		case OPCODE_DATA_MAILCHECK:
		{
			printf("Received DATA_MAILCHECK\n");
			uint8_t uRes[] = {0x00, 0x01 };
			printf("Sending MAILCHECK_OK\n");
			//More like "NEW_NONE"
			sendPacket30((uint8_t*)uRes,sizeof(uRes),OPCODE_DATA_MAILCHECK_OK);
			break;
		}
			
		case OPCODE_DATA_NEWCHECK:
		{
			printf("Received DATA_NEWS_CHECK\n");
			uint8_t uRes[] = {0x00, 0x00};
			printf("sending NEWCHECK_OK\n");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_NEWCHECK_OK);
			break;
		}																																																																																																									
																																																																																																																																																																																																																																																																													

		
		case OPCODE_DATA_REGISTER_CHAR:
		{
			// Argument given (everything else has to be a hacking attempt and will be ignored here)
			if (aSize > 24)
			{
				// Terminate Packet (to prevent possible overflow through hacking attempt)
				arg[aSize - 1] = 0;

				// Cast Arguments
				uint8_t * saveSlot = arg;
				char * saveID = (char *)saveSlot + 1;
				char * characterName = saveID + strlen(saveID) + 1;

				// Prevent Save ID Overflow Hacking Attempts
				if (characterName < (char *)(arg + aSize))
				{
					// Cast Arguments
					uint8_t * characterClass = (uint8_t *)characterName + strlen(characterName) + 1;

					// Prevent Character Name Overflow Hacking Attempts
					if (characterClass < (arg + aSize))
					{
						// Prevent Character Class Index Overflow Hacking Attempts
						if (*characterClass >= CLASS_TWINBLADE && *characterClass <= CLASS_WAVEMASTER)
						{
							// Cast Arguments
							uint16_t * characterLevel = (uint16_t *)(characterClass + 1);
							char * greeting = (char *)&characterLevel[1];

							// Prevent Character Greeting Overflow Hacking Attempts
							if (greeting < (char *)(arg + aSize))
							{
								// Calculate Offset past last known Field
								uint16_t * pastUnk2 = (uint16_t *)(greeting + strlen(greeting) + 1 /* null-terminator */ + 1 /* unk1 */ + 2 /* HP */ + 2 /* SP */+ 4 /* GP */ + 2 /* Offline Gott-Statue Counter */ + 2 /* Online Gott-Statue Counter */+ 2 /* unk2 */);

								// Prevent Followup Character Greeting Overflow Hacking Attempts
								if (pastUnk2 < (uint16_t *)(arg + aSize))
								{
									// Cast Static Fields
									uint32_t * characterModel = (uint32_t *)(greeting + strlen(greeting) + 1);
									uint8_t * unk1 = (uint8_t *)&characterModel[1];
									uint16_t * characterHP = (uint16_t *)&unk1[1];
									uint16_t * characterSP = (uint16_t *)&characterHP[1];
									uint32_t * characterGP = (uint32_t *)&characterSP[1];
									uint16_t * offlineGodCounter = (uint16_t *)&characterGP[1];
									uint16_t * onlineGodCounter = (uint16_t *)&offlineGodCounter[1];
									// uint16_t * unk2 = (uint16_t *)&onlineGodCounter[1];

									// Prevent non-critical but annoying invalid data Hacking Attempts
									if (ntohs(*characterLevel) >= MIN_CHARACTER_LEVEL && ntohs(*characterLevel) <= MAX_CHARACTER_LEVEL)
									{
										// Store Data into Client Object
										this->activeCharacterClass = *characterClass;
										this->activeCharacterLevel = ntohs(*characterLevel);
										this->activeCharacterModel = ntohl(*characterModel);
										this->activeCharacterHP = ntohs(*characterHP);
										this->activeCharacterSP = ntohs(*characterSP);
										this->activeCharacterGP = ntohl(*characterGP);
										this->activeCharacterOfflineGodCounter = ntohs(*offlineGodCounter);
										this->activeCharacterOnlineGodCounter = ntohs(*onlineGodCounter);
										strncpy(this->activeCharacterSaveID, saveID, sizeof(this->activeCharacterSaveID));
										strncpy(this->activeCharacter, characterName, sizeof(this->activeCharacter));
										strncpy(this->activeCharacterGreeting, greeting, sizeof(this->activeCharacterGreeting));
									}
								}
							}
						}
					}
				}
			}
			else
			{
				printf("OPCODE_DATA_REGISTER_CHAR INCOMPLETE\n");
			}

			// Notify Administrator
			printf("RECEIVED DATA_REGISTER_CHAR!\n");

			// Send Default Response to Client
			uint8_t uRes[] = {0x00,0x00};
			printf("Sending REGISTER_CHAROK\n");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_REGISTER_CHAROK);
			break;				
		}
		
		case OPCODE_DATA_UNREGISTER_CHAR:
		{
			// Wipe Character Identification Data from Object
			this->activeCharacterClass = CLASS_TWINBLADE;
			this->activeCharacterLevel = 0;
			this->activeCharacterModel = 0;
			this->activeCharacterHP = 0;
			this->activeCharacterSP = 0;
			this->activeCharacterGP = 0;
			this->activeCharacterOfflineGodCounter = 0;
			this->activeCharacterOnlineGodCounter = 0;
			memset(this->activeCharacterSaveID, 0, sizeof(this->activeCharacterSaveID));
			memset(this->activeCharacter, 0, sizeof(this->activeCharacter));
			memset(this->activeCharacterGreeting, 0, sizeof(this->activeCharacterGreeting));

			// Send Default Response to Client
			printf("RECEIVED DATA_UNREGISTER_CHAR\n");
			uint8_t uRes[] = {0x00,0x00};
			printf("Sending UNREGISTER_CHAROK\n");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_UNREGISTER_CHAROK);
			break;
		}
		
		case OPCODE_DATA_SELECT_CHAR:
		{
			// Argument given (everything else has to be a hacking attempt and will be ignored here)
			if (aSize > 0)
			{
				// Terminate Packet (to prevent possible overflow through hacking attempt)
				arg[aSize - 1] = 0;

				// Cast Arguments
				char * diskID = (char *)arg;
				char * saveID = diskID + strlen(diskID) + 1;

				// Prevent Disk ID Overflow Hacking Attempts
				if (saveID < (char *)(arg + aSize))
				{
					// Cast Arguments
					uint8_t * unk1 = (uint8_t *)saveID + strlen(saveID) + 1;

					// Prevent Save ID Overflow Hacking Attempts
					if (unk1 < (arg + aSize))
					{
						// Cast Arguments
						char * characterSaveID = (char *)&unk1[1];

						// Prevent Followup Save ID Hacking Attempts
						if (characterSaveID < (char *)(arg + aSize))
						{
							// Store Data into Client Object
							strncpy(this->diskID, diskID, sizeof(this->diskID));
							strncpy(this->saveID, saveID, sizeof(this->saveID));
							strncpy(this->activeCharacterSaveID, characterSaveID, sizeof(this->activeCharacterSaveID));
						}
					}
				}
			}
			else
			{
				printf("OPCODE_DATA_SELECT_CHAR INCOMPLETE\n");
			}

			// Send Default Response to Client
			printf("RECEIVED DATA_SELECT_CHAR\n");
			uint8_t uRes[] = {0x00,0x00};
			printf("Sending SELECT_CHAROK\n");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_SELECT_CHAROK);
			break;
		}
		
		
		case OPCODE_DATA_SELECT2_CHAR:
		{
			printf("RECEIVED DATA_SELECT2_CHAR\n");
			//uint8_t uRes[] = {0x00,0x00};
			printf("Sending SELECT2_CHAROK\n");
			sendPacket30(arg,sizeof(arg),OPCODE_DATA_SELECT2_CHAROK);
			break;
		}

		
		case OPCODE_DATA_NEWS_GETPOST:
		{
			uint16_t pId = ntohs(*(uint16_t*)(arg));
			sendNewsPost(pId);
			break;		
		}		
		
		case OPCODE_DATA_NEWS_GETMENU:
		{

			uint16_t nID = ntohs(*(uint16_t*)(arg));
			if(nID == 0)
			{
				printf("RETREIVING NEWS CATEGORY LIST!\n");
				sendNewsCategories();
			}
			else
			{
				sendNewsPostList(nID);
			}
						
												
																								
			break;
		}


		case OPCODE_DATA_RETURN_DESKTOP:
		{
			printf("RECEIVED DATA_RETURN_DESKTOP\n");
			uint8_t uRes[] = {0x00,0x00};
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_RETURN_DESKTOP_OK);
			
			break;	
		}	


		case 0x7862:
		{
			// could this be OPCODE_DATA_SEND_GREETING?
			/*
				uint16_t unk1;
				uint16_t unk2;
				uint8_t unk3;
				uint32_t unk4;
				uint32_t unk5;
				uint32_t unk6;
				uint8_t messageLength; // in bytes
				uint8_t message[]; // messageLength bytes long (null terminator is counted)
			*/
			printf("RECEIVED LOBBY_???\n");
			uint8_t uRes[] = {0x00,0x01,0x30,0x30,0x30,0x30,0x30,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x82,0x61,0x82,0x74,0x82,0x6b,0x82,0x6a,0x82,0x71,0x82,0x6e,0x82,0x72,0x82,0x64};
			sendPacket30(uRes,sizeof(uRes),0x7847);
			
			uint8_t uRes2[] = {0x30,0x30,0x30,0x30,0x30,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x82,0x61,0x82,0x74,0x82,0x6b,0x82,0x6a,0x82,0x71,0x82,0x6e,0x82,0x72,0x82,0x64};
			sendPacket30(uRes2,sizeof(uRes2),0x7847);
			
//			uint8_t uRes2[] = {0x00,0x01,0x0c,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x82,0x61,0x82,0x74,0x82,0x6b,0x82,0x6a,0x82,0x71,0x82,0x6e,0x82,0x72,0x82,0x64};
	//		sendPacket30(uRes2,sizeof(uRes2),0x7862);
		//	uint8_t uRes3[] = {0x00,0x01,0x0c,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x82,0x61,0x82,0x74,0x82,0x6b,0x82,0x6a,0x82,0x71,0x82,0x6e,0x82,0x72,0x82,0x64};
			//sendPacket30(uRes3,sizeof(uRes3),0x7862);
			
			
			
			
			break;
		}

		case 0x780f:
		{
			//create_thread_title?
			printf("RECIEVED CREATE_THREAD_TITLE\n");
			uint8_t uRes[] = {0x01,0x92};
			sendPacket30(uRes,sizeof(uRes),0x7810);
			
			
			break;
			
			
		}

		case OPCODE_DATA_LOBBY_CHATROOM_CREATE:
		{
			printf("RECIEVED	CHATROOM_CREATE!\n");
			uint8_t uRes[] = {0x00,0x01};
			sendPacket30(uRes,sizeof(uRes),0x7414); //successful
			
			//7414 duplicate name or in use	
			//7417 duplicate name or in use
			//7413 DUPLICATE NAME OR IN USE
			//7416 successful
						
			
			
			break;
		}

		case 0x7412:
		//create chatroom, no-password.
		{
			printf("RECEIVED	GET	CHATROOM	INFO!\n");
			uint8_t uRes [] = {0x00,0x00};
			sendPacket30(uRes,sizeof(uRes),0x7416);
			//sendPacket30(uRes,sizeof(uRes),0x7415);
			
			//7413 GET SETTING FAILED			
			//7414 duplicate name or in use
			//7416 - successful...
			//7417 - name in use...			
			
			break;
		}

		case OPCODE_DATA_LOBBY_CHATROOM_GETLIST:
		{
			printf("RECEIEVED LOBBY_CHATROOM_GETLIST\n");
			
			//				  [ unk   ][room name                                                  ][unk               ][ Num U  ]								
	//		uint8_t uNum[] = {0x00, 0x01,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x00};
			uint8_t uNum[] = {0x00,0x00,0x00,0x02,0x00,0x00};
			
			//uint8_t uCht[] = {0x00,0x00,0x46,0x55,0x43,0x4b,0x00,0x66,0x75,0x63,0x6b,0x00};
					//		 [id     ] [room name                                                ] [unk    ] [Unk    ] [ Num U ] [St     ?]	
			uint8_t uRes[] =  {0x00,0x00,0x46,0x61,0x6b,0x65,0x20,0x43,0x68,0x61,0x74,0x20,0x31,0x00,0xFf,0xFf,0xFf,0xFf,0x00,0x01,0x02,0x00,0x00,0x01,0x00,0x02};
			//uint8_t uRes2[] = {0x00,0x02,0x46,0x61,0x6b,0x65,0x20,0x43,0x68,0x61,0x74,0x20,0x32,0x00,0x31,0x31,0x31,0x00,0x00,0x02,0x00,0x00};
			uint8_t uRes3[] = {0x00,0x02,0x46,0x61,0x6b,0x65,0x20,0x43,0x68,0x61,0x74,0x20,0x32,0x00,0x00,0x01,0x00,0x01,0x00,0x01,0x00,0x01};                             
			//			    [id   ]    [room name                                              ]   [unk     ][Unk    ][ Num U  ][St     ?]								                                          
			//				0            2                                                          14        16        18       20                 
						
			sendPacket30(uNum,sizeof(uNum),OPCODE_DATA_LOBBY_CHATROOM_CATEGORY);
			
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_LOBBY_CHATROOM_LISTERROR);
			
			sendPacket30(uRes3,sizeof(uRes3),OPCODE_DATA_LOBBY_CHATROOM_LISTERROR);
			
			
			uint8_t uNum2[] = {0x00,0x01,0x00,0x02};
			
						
			sendPacket30(uNum2,sizeof(uNum2),OPCODE_DATA_LOBBY_CHATROOM_CATEGORY);
			
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_LOBBY_CHATROOM_LISTERROR);
			
			sendPacket30(uRes3,sizeof(uRes3),OPCODE_DATA_LOBBY_CHATROOM_LISTERROR);
			
			
			
			
			/*
			0x7407
			struct
			{
				uint16_t unk1;
				uint16_t unk2;
			}
			
			0x7408		
			struct
			{
				uint16_t unk0 //0
				uint16_t unk1 //14
				uint16_t unk2 //16
				uint16_t numUsers //18
				uint16_t status //20
					< 0x0100 = unavailable. > 0x00ff = available
					
			}
			
			*/	
												
			
			break;
		}

		case OPCODE_DATA_BBS_GETMENU:
		{
			//BBS_GET_THREADS
			printf("BBS_GET_THREADS");
			
			// Minimal Argument Size
			if (aSize >= 2)
			{
				uint16_t catID = ntohs(*(uint16_t*)(arg));
			
				if(catID == 0)
				{
					uint8_t uRes[] = {0x00,0x01};
					sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_BBS_CATEGORYLIST);
			
			
					uint8_t uRes2[36] = {0};
					uint16_t * catID = (uint16_t *)uRes2;
					uint8_t * catName = (uint8_t *)&catID[1];
					*catID = htons(1);
					snprintf((char*)catName,33,"This is not a real cat yet...");
					sendPacket30(uRes2,sizeof(uRes2),OPCODE_DATA_BBS_ENTRY_CATEGORY);			
				}
				else
				{
					uint8_t uRes[] = {0x00,0x01};
					sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_BBS_THREADLIST);
				
					uint8_t uRes2[38] = {0};
					uint32_t * thID = (uint32_t *)uRes2;
					//uint16_t * thID = (uint16_t *)uRes2;
					//uint16_t * thUnk = &thID[1];
					uint8_t * thName = (uint8_t *)&thID[1];
					*thID = htonl(0x1);
					snprintf((char*)thName,33,"This is not a real thread...yet.");
					sendPacket30(uRes2,sizeof(uRes2),OPCODE_DATA_BBS_ENTRY_THREAD);
					//struct threadList
					//{
					//	uint32_t threadId
					//	char *threadName
					//
					//
								
																
				}			
				//7849 threadCat
				//784a error
				//784b catEnrty
				//784c threadList
				//784d threadEnrty
			}
			else
			{
				printf("OPCODE_DATA_BBS_GETMENU INCOMPLETE\n");
			}
			
			
			break;
		}

		
		case 0x781c:
		{
			printf("RECEIVED BBS_POST_GET_DETAILS\n");
			uint8_t uRes[] = {0x00, 0x00, 0x00, 0x00, 0x54,0x48,0x49,0x53,0x20,0x49,0x53,0x20,0x41,0x20,0x54,0x45,0x53,0x54,0x20,0x50,0x4f,0x53,0x54,0x21,0x0a,0x42,0x49,0x54,0x43,0x48,0x45,0x53,0x21,0x00,0x42,0x49,0x54,0x43,0x48,0x45,0x53,0x21,0x00,0x54,0x48,0x49,0x53,0x00};
			sendPacket30(uRes,sizeof(uRes),0x781d);
			/*
			OPCODE_DATA_BBS_POST_DETAILS:
			struct
			{
				uint32_t unknown
				char *postText
						
			}			
												
			*/			
			
			break;
		}
						

		case 0x787e:
		{
			printf("ENTER RANKING SCREEN\n");
			uint8_t uRes[] = {0x00, 0x00};
			sendPacket30(uRes, sizeof(uRes),0x787f);
			
			break;
			
		}
			
									
		case 0x7832:
		{
			//Get Ranking,
			//Arg 0x00 = TOP PAGE, show what to sort the ranking by.
			//Arg > 0x00 = Ranking Category.
			 			       
			printf("GET RANKING\n");
			
			// Minimal Argument Size
			if (aSize >= 2)
			{
				uint16_t rankCat = ntohs(*(uint16_t*)(arg));
				if(rankCat == 0)
				{
					printf("TYPE: %04X\n",rankCat);
					uint8_t uRes[] = {0x00,0x02};
			
					sendPacket30(uRes,sizeof(uRes),0x7833);
			
			
					uint8_t uRes2[] = {0x00,0x01, 0x30, 0x30,0x00, 0x00, 0x01};
			
					sendPacket30(uRes2, sizeof(uRes2), 0x7835);
					uRes2[1] = 0x02;
					sendPacket30(uRes2, sizeof(uRes2), 0x7835);
				}
				else
				{
					printf("CAT: %04X\n",rankCat);
					uint8_t uRes[] = {0x00, 0x00,0x00,0x01};
					sendPacket30(uRes, sizeof(uRes),0x7836);
					uint8_t uRes2[] = {0x30,0x00, 0x00,0x00,0x00,0x01,0x30,0x00};
					sendPacket30(uRes2,sizeof(uRes2),0x7837);
					//uRes2[0] = 0x02;
					//uRes2[4] = 0x02;
					//sendPacket30(uRes2,sizeof(uRes2),0x7837);
				
				
				}
			}
			else
			{
				printf("7832 INCOMPLETE\n");
			}
			
			break;
			//0x7833 - numCategory
			//0x7834 - Error
			//0x7835 - Category
			/*struct
			{
				uint16_t catID;
				char *catName; presumably up to 32b before truncation.
				
			}
			*/
			//0x7836 - numEntries
			/*
			struct
			{
				uint16_t unk = 0x0000 //always blank for some reason?
				uint16_T numEntries
			}
			*/
			
			//0x7837 - Entry
			/*
			struct
			{
				char* userName;
				uint32_t playerID;	
				
				
				
			}												
			*/																								
																																																			
		}																	


		case 0x7838:
		{
			//get Ranked character info.
			printf("GET RANKED CHARACTER INFO!\n");
			//	           [name                                  ] [cls][LVL    ][Greeting?]  [Guild Name]                                                                [mDetails          ] [online?] [       ] [Guild Status]                                     
			uint8_t uRes[] = {0x4e,0x43,0x44,0x79,0x73,0x6f,0x6e,0x00,0x00,0x00,0x01,0x61,0x00,  0x44,0x61,0x79,0x62,0x72,0x65,0x61,0x6b,0x20,0x4d,0x61,0x66,0x69,0x61,0x00, 0x00,0x00,0x00,0x00, 0x01,     0x00,0xfe,0x02,         0x30,0x30,0x00};
			//	 0  1         2    3    4    5    6    7    8    9    a    b    c    d    e      f                   10    11   12   13    14            15    16   17  18   19  
			sendPacket30(uRes,sizeof(uRes),0x7839);
		
		
			break;
		/*
		struct
		{
			char * name;
			uint8_t class
			uint16_t level
			char * desc //This is either greeting or something else, still looking into this...
			char * guildName //only displays wil valid guildStatus
			uint32_t modelDetails; //same used in the character UpdateInfo packet...
			uint8_t onlineStatus //0 = offline, 1 = online
			uint16_t unknown //currently unknown...
			uint8_t guildStatus
			//0 = None
			//1 = Master
			//2 = Member
			
			
		
		}
		*/
		
		}
																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																																								
		case OPCODE_DATA_BBS_THREAD_GETMENU:
		{

			//7819
			//781a
			//781b			
			printf("Getting THREAD!\n");
			uint8_t uRes[] = {0x00,0x00,0x00,0x02};//
			//OPCODE_DATA_BBS_THREAD_LIST
				//uint32_t ???
			//sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_BBS_THREAD_GETMENU_FAILED);
			//uint8_t uRes[] = {0x00,0x02};
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_BBS_THREAD_LIST);
			
			//  			  [unk			   ]  [postID		   ]  [unk2]               [date (sub 9hrs)        [userName, truncates(w/ "..." after 16 characters(15 + null terminator                ] [subTitle? truncates(no ...) after 18 char, (17 + 0x00)                                     ]   [unk 44b                                                                                                                                                                                                                       ]   [ post title, truncates(w/ "...") after 33 (32 + 0x00)                                                                                                                                                                  ]	  			
			uint8_t tmpT[] =  {0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x00, 0x53,0x62,0xa7,0xc0,    0x30,0x31,0x32,0x33, 0x34,0x35,0x36,0x37, 0x38,0x39,0x61,0x62, 0x63,0x64,0x65,0x66,0x00, 0x67,0x68,0x69,0x6a, 0x6b,0x6c,0x6d,0x6e, 0x6f,0x70,0x71,0x72, 0x73,0x74,0x75,0x76, 0x77,0x00, 0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x00,  0x31,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x64,0x00 };
			uint8_t tmpT2[] = {0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x02, 0x00,0x00,0x00,0x00, 0x53,0x62,0xa7,0xc0,    0x30,0x31,0x32,0x33, 0x34,0x35,0x36,0x37, 0x38,0x39,0x61,0x62, 0x63,0x64,0x65,0x66,0x00, 0x67,0x68,0x69,0x6a, 0x6b,0x6c,0x6d,0x6e, 0x6f,0x70,0x71,0x72, 0x73,0x74,0x75,0x76, 0x77,0x00, 0x00,0x00,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x30,0x31,0x00,  0x33,0x34,0x35,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x63,0x64,0x00 };
						
			//uint8_t tmpT2[] = {0x00,0x00,0x00,0x01, 0x00,0x00,0x00,0x03, 0x00,0x00,0x00,0x01, 0x00};
			
			
			sendPacket30(tmpT,sizeof(tmpT),0x781a);
			sendPacket30(tmpT2,sizeof(tmpT2),0x781a);
			//sendPacket30(tmpT2,sizeof(tmpT2),0x781b);
			//0x781b = failed to get article list...
			/*
			0x781a
			struct
			{
				uint32_t unk1
				uint32_t postID
				uint32_t unk2
				uint32_t date; //have to minus 9 hours to get correct date...
				char * userName //after 17b (16 + null term) it will display truncated(with "...")
				char * threadSUBTITLE //after 18b (17b + nullterm) it will display truncated (without "...")
				uint8_t emptyField[45] //empty field. if it's used, it sure as hell doesn't display on screen...
				char * postTitle//after 33b(32 + nullterm) it will display truncated (with "...")
				
		}
		*/
			
			//sendPacket30(tmpT,sizeof(tmpT),0x781b);
			
			break;
		}
				
						
		case OPCODE_DATA_BBS_GET_UPDATES:
		{
			printf("RECEIVED DATA_BBS_GET_UPDATES\n");
			uint8_t uRes[] = {0x00,0x00};
			//tell it no?
			sendPacket30(uRes,sizeof(uRes),0x786b);
											
			break;												
		}				
								
		case OPCODE_DATA_LOBBY_ENTERROOM:
		{
			printf("RECEIVED DATA_LOBBY_ENTERROOM\n");
			
			uint8_t uRes[] = {0x00,0x01};
			printf("Sending DATA_LOBBY_ENTEROOM_OK");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_LOBBY_ENTERROOM_OK);
						
			uint8_t uRes2[] = {0x00,0x01,0x00,0x0c,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x06,0x57,0x4f,0x4e,0x47,0x46,0x55,0x00};

			sendPacket30(uRes2,sizeof(uRes2),0x7009);

			
			
																		
																								
			break;
			
		}
			
				
		/*
		0x7007		
			ENTER_ROOM_OK
		0x7009
			unknown
		0x740b
			unknown
		0x740e
			unknown
		0x781f
			"You've become room master"
							
								
														
		*/				
						
								
										
														
		case 0x7009:
		{
			//7009 seems to be "LOBBY_FUNC?"
			printf("RECEIVED 0x7009\n");
			printf("sending OK\n");
			//uint8_t uRes[] = {0x00,0x05,0x30,0x00,0x31,0x00,0x32,0x00,0x33,0x00};
			//sendPacket30(uRes,sizeof(uRes),0x700a);

			//010002000000000000000000000000000010000000000000ff0000010000003c000000e8030000
									
			//uint8_t uRes2[] = {0x01,0x00,0x02,0x00,0x30,0x00};
			uint8_t uRes3[] = {0x00,0x01,0x00,0x01, 0x30,0x31,0x32,0x33,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x40,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x00,0x00,0x01,0x00,0x00,0x00,0x3c,0x00,0x00,0x00,0xe7,0x03,0x00,0x00};
			sendPacket30(uRes3,sizeof(uRes3),0x7009);
//			sendPacket30(uRes2,sizeof(uRes2),0x740b);
//			sendPacket30(uRes2,sizeof(uRes2),0x740e);
//			sendPacket30(uRes2,sizeof(uRes2),0x7009);
//			uint8_t uRes3[] = {0x00,0x01,0x00,0x0c,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x4e,0x43,0x44,0x59,0x53,0x4f,0x4e,0x00};			
//			uint8_t uRes4[] = {0x00,0x01,0x00,0x0c,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x08,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x00};						
//			sendPacket30(uRes3,sizeof(uRes3),0x7862);										
//			sendPacket30(uRes4,sizeof(uRes4),0x7862);															
																		
				
			break;
		}         		 		                           		 		                                  		  			                		 		                          
		
		case OPCODE_DATA_LOBBY_GETSERVERS:
		{
			printf("RECEIVED DATA_LOBBY_GETSERVERS\n");
			uint8_t uRes[] = {0x00,0x00};
			printf("SENDING RESPONSE\n");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_LOBBY_GETSERVERS_OK);
			
		//	uint8_t uRes2[] = {0x00,0x00};
			//sendPacket30(uRes2,sizeof(uRes2),OPCODE_DATA_LOBBY_GETSERVERS_ENTRY);
			
			break;
			
		}
			
			
		case OPCODE_DATA_LOBBY_GETSERVERS_EXIT:
		{
			printf("RECEIVED DATA_LOBBY_GETSERVERS_EXIT\n");
			uint8_t uRes[] = {0x00,0x00};
			printf("Sending Ok\n");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_LOBBY_GETSERVERS_EXIT_OK);
			
			
			
			break;
		}
			
		case OPCODE_DATA_LOBBY_GETSERVERS_GETLIST:
		{
			printf("RECEIVED DATA_LOBBY_GETSERVERS_GETLIST\n");
			
			if (aSize >= 2)
			{
				uint16_t lID = ntohs(*(uint16_t*)(arg));			
				if(lID == 0x01)
				{
					std::list<AreaServer *> * areaServers = Server::getInstance()->GetAreaServerList();
					uint8_t rServerNum[2];
					uint16_t * numServers = (uint16_t*)rServerNum;
					*numServers = htons(areaServers->size());
				
					sendPacket30(rServerNum,sizeof(rServerNum),OPCODE_DATA_LOBBY_GETSERVERS_SERVERLIST);					
					uint8_t uRes[AS_LIST_LINE_MAXSIZE] = {0};
					//iterate through all area servers to get their listings...
					for(std::list<AreaServer *>::iterator it = areaServers->begin(); it != areaServers->end();/*takes care of itself...*/)
					{
						AreaServer * as = *it;
						as->GetServerLine(uRes,sizeof(uRes),this->asExtAddr, GetAntiCheatEngineResult());
						sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_LOBBY_GETSERVERS_ENTRY_SERVER);
											
						it++;				
					
					}


					/*
					struct lobbyEntry
					{
						uint8_t unk1;
						uint32_t IP;
						uint16_t Port;
						uint8_t name; //nullTerminated
						uint16_t Level;
						uint16_t sType;
						uint16_t pcs;
						uint8_t sStatus;
						uint8_t ID;
					}
				
					*/								
									
				}
				else
				{		
					uint8_t uRes[] = {0x00,0x01};
					sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_LOBBY_GETSERVERS_CATEGORYLIST);
			

					uint8_t uRes2[38];
					uint16_t * dID = (uint16_t*)uRes2;
					char * dName = (char *)&dID[1];
				
					*dID = htons(0x01);
					strncpy(dName,"MAIN",34);
				
					sendPacket30(uRes2,sizeof(uRes2),OPCODE_DATA_LOBBY_GETSERVERS_ENTRY_CATEGORY);
				}
			}
			else
			{
				printf("OPCODE_DATA_LOBBY_GETSERVERS_GETLIST INCOMPLETE\n");
			}
			
			break;
		}			

		
		
		
		case OPCODE_DATA_LOBBY_EXITROOM:
		{
			printf("RECEIVED DATA_LOBBY_EXITROOM\n");
			
			uint8_t uRes[] = {0x00,0x00};
			printf("Sending DATA_LOBBY_EXITROOM_OK\n");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_LOBBY_EXITROOM_OK);
			
			
			
			break;
			
		}
		
		case OPCODE_DATA_LOBBY_GETMENU:
		{

			
						
			printf("RECEIVED DATA_LOBBY_GETMENU\n");

			// Minimal Argument Size
			if (aSize >= 2)
			{
				uint16_t lID = ntohs(*(uint16_t*)(arg));

				if(lID == 1)
				{
					//uint16_t entryID, char*name,uint16_t numUsers, uint8_t lobbyStatus?
					//uint8_t uRes2[] = {0x00,0x01,0x54,0x68,0x69,0x73,0x20,0x69,0x73,0x20,0x6e,0x6f,0x74,0x20,0x61,0x20,0x72,0x65,0x61,0x6c,0x20,0x73,0x65,0x72,0x76,0x65,0x72,0x2e,0x2e,0x2e,0x79,0x65,0x74,0x00,0x00,0x01,0x00,0x02};
					uint8_t uRes2[50];
					uint16_t * eID = (uint16_t*)uRes2;
					char * eName = (char *)&eID[1];
				
					*eID = htons(0x01);
					strncpy(eName,"Main",34);
					uint16_t eNameLen = strlen(eName);
					uint16_t * eNumUsers = (uint16_t *)&eName[eNameLen + 1];
					uint16_t * eLobbyStatus = &eNumUsers[1];
				
					*eNumUsers = htons(0);
					*eLobbyStatus = htons(0x01); //0 = RED X, 1 = OK.
				
										
								
																								
					uint8_t uRes[] = {0x00,0x01}; //number of lobbies
					printf("Sending LOBBY_ENTRY_SERVER\n");
					sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_LOBBY_LOBBYLIST);
				
				
					printf("Sending LOBBY_ENTRY_SERVER\n");
					sendPacket30(uRes2,sizeof(uRes2),OPCODE_DATA_LOBBY_ENTRY_LOBBY);				
				
				}
				else
				{
					uint8_t uRes2[39] = {0};


					uint8_t uRes[] = {0x00,0x01}; //number of categories
					printf("Sending LOBBY_GETMENU_OK\n");
					sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_LOBBY_CATEGORYLIST);

					//dirty hack...
					uRes2[1] = 0x01;			
					sprintf((char *)uRes2 + sizeof(uint16_t),"All Lobbies");
			
					printf("Trying to send a lobby list entry...\n");
					sendPacket30(uRes2,sizeof(uRes2),OPCODE_DATA_LOBBY_ENTRY_CATEGORY);
												
				}
			}
			else
			{
				printf("OPCODE_DATA_LOBBY_GETMENU INCOMPLETE\n");
			}

			break;
		}
						

		case OPCODE_DATA_MAIL_GET:
		{
			printf("RECEIVED DATA_MAIL_GET\n");
			uint8_t uRes[] = {0x00,0x06};
			printf("Sending MAIL_GETOK\n");
			sendPacket30(uRes,sizeof(uRes),0x7804);
					
					
					
			/*
			
			7804:
						
			
			
			
			
			7805:
				"Failed to get Mail Header"
				
			
			*/
					
			break;				
		}		



		case 0x7733:
		{
			//Get Guild List, standard interactive menu affair?
			if (aSize >= 2)
			{
				uint16_t cID = ntohs(*(uint16_t*)(arg));

				if(cID == 0x00)
				{
					printf("Get Guild List Categories!\n");
					uint8_t uRes[] = {0x00,0x01};
					sendPacket30(uRes,sizeof(uRes),0x7734);
					uint8_t uCat[] = {0x00,0x01,0x41,0x6c,0x6c,0x00};
					sendPacket30(uCat,sizeof(uCat),0x7736);
			
				}
				else
				{
				
					printf("GET GUILD, CATEGORY: %u\n",cID);
					uint8_t uRes[] = {0x00,0x01};
					sendPacket30(uRes,sizeof(uRes),0x7737);
					uint8_t uEntry[] = {0x00,0x01, 0x44,0x61,0x79,0x62,0x72,0x65,0x61,0x6b,0x20,0x4d,0x61,0x66,0x69,0x61,0x00}; 
					sendPacket30(uEntry,sizeof(uEntry),0x7738);
				}
			}
			else
			{
				printf("7733 INCOMPLETE\n");
			}
		/*
		//0x7734 numCats
		struct
		{
			uint16_t numCats
		}
		
		//0x7735 Error
		
		//0x7736 category
		struct
		{
			uint16_t catID
			char *catName
		}
		
		//0x7737 numEntries
		struct
		{
			uint16_t numEntries
		}
		
		//0x7738 Entry
		struct
		{
			uint16_t entryID;
			char *entryName;
		}
		
		
		*/
		
		
			break;
		}
		
		
		case 0x7739:
		{
			//get guild info
			printf("GET GUILD INFO!\n");
			uint8_t uRes[]  = {0x30,0x00, 0x31,0x00, 0x32, 0x00,   0x00,0x01, 0x00,0x02, 0x00,0x03, 0x00,0x04, 0x00,0x05, 0x00,0x06, 0x00,0x07};
			sendPacket30(uRes,sizeof(uRes),0x7741);
			
			
			/*
			0x7740
			struct
			{
				char *guildName;  		//0x30,0x00
				char *establishedDate;	//0x31,0x00 
				char *guildMaster;		//0x32,0x00
				//membership
				uint16_t membersTotal;	//0x00,0x01
				uint16_t numTwinBlades;   //0x00,0x02		
				uint16_t numBladeMasters; //0x00,0x03
				uint16_t numHeavyBlades;  //0x00,0x04
				uint16_t numHeavyAxes;    //0x00,0x05
				uint16_t numLongArms;     //0x00,0x06
				uint16_t numWaveMasters;  //0x00,0x07
				uint16_t averageLevel;    
				//guild assets
				uint32_t goldCoins;
				uint32_t silverCoins;
				uint32_t copperCoins;
				uint32_t GP;
				//otherShit
				char* guildComment
			}
			
			0x7741
				//failed to get guild information.
			
			*/
						
			
			
			break;
		}
		
		
		case 0x7722:
		{
			// Minimal Argument Size
			if (aSize >= 2)
			{
				//standard interactive menu affair...
				uint16_t cID = ntohs(*(uint16_t*)(arg));
			
				if(cID == 0x0)
				{
					printf("GET GUILD SHOP CATEGORY LIST!\n");
					uint8_t uRes[] = {0x00,0x01};
					uint8_t uCat[] = {0x00,0x01, 0x41, 0x6c, 0x6c,0x00};
					sendPacket30(uRes,sizeof(uRes),0x7723);
					sendPacket30(uCat,sizeof(uCat),0x7725);
				}
				else
				{
					printf("GET GUILD SHOP, CATEGORY: %u\n",cID); 
					uint8_t uRes[] = {0x00,0x01};
					uint8_t uEnt[] = {0x00,0x01, 0x44,0x61,0x79,0x62,0x72,0x65,0x61,0x6b,0x20,0x4d,0x61,0x66,0x69,0x61,0x00};
					sendPacket30(uRes,sizeof(uRes),0x7726);
					sendPacket30(uEnt,sizeof(uEnt),0x7727);
				}
			}
			else
			{
				printf("7722 INCOMPLETE\n");
			}
			
			/*
			7723 numcat
			7724 err
			7725 cat
			7726 nument
			7727 ent
			
			
			
			
			*/
			
			
			
			break;
		}
		
		
		case 0x772f:
		{
			// Minimal Argument Size
			if (aSize >= 2)
			{
				uint16_t gID = ntohs(*(uint16_t*)(arg));
			
				//get guild shop item list...	
				printf("Get Guild Shop Items. GID: %u\n",gID);
				uint8_t uRes[] = {0x00,0x01};
				sendPacket30(uRes,sizeof(uRes),0x7730);
		
		
				//uint8_t uRes2[] = {0x00,0x00, 0x00,0x00, 0x00,0xff, 0x00,0x00,0x00,0x01};
				uint8_t uRes2[] = {0x00,0x00, 0x00,0x00, 0x00,0xff, 0x00,0x07,0xA1,0x20};
			/*
				sendPacket30(uRes2,sizeof(uRes2),0x7731);
			
				uRes2[1] = 0x01;
				sendPacket30(uRes2,sizeof(uRes2),0x7731);
			
				uRes2[1] = 0x02;
				sendPacket30(uRes2,sizeof(uRes2),0x7731);
			
				uRes2[1] = 0x03;
				sendPacket30(uRes2,sizeof(uRes2),0x7731);
			
				uRes2[1] = 0x04;
				sendPacket30(uRes2,sizeof(uRes2),0x7731);
			
				uRes2[1] = 0x05;
				sendPacket30(uRes2,sizeof(uRes2),0x7731);
			
				uRes2[1] = 0x06;
				sendPacket30(uRes2,sizeof(uRes2),0x7731);
			
				uRes2[1] = 0x07;
				sendPacket30(uRes2,sizeof(uRes2),0x7731);
			
				uRes2[1] = 0x08;
				sendPacket30(uRes2,sizeof(uRes2),0x7731);
			
				uRes2[1] = 0x09;
				sendPacket30(uRes2,sizeof(uRes2),0x7731);
			
				uRes2[1] = 0x0a;
				sendPacket30(uRes2,sizeof(uRes2),0x7731);
			
				uRes2[1] = 0x0b;
				sendPacket30(uRes2,sizeof(uRes2),0x7731);
			
				uRes2[1] = 0x0c;
				sendPacket30(uRes2,sizeof(uRes2),0x7731);
			
				uRes2[1] = 0x0d;
				sendPacket30(uRes2,sizeof(uRes2),0x7731);
				*/
				uRes2[1] = 0x0e;
				uRes2[3] = 0x2b;
				sendPacket30(uRes2,sizeof(uRes2),0x7731);
			
			//	uRes2[1] = 0x0f;
				//sendPacket30(uRes2,sizeof(uRes2),0x7731);
			
			
			
				/*
				7730 numItems?
				7731 shopItem 
			
				struct
				{
					uint16_t type
					uint16_t number
					uint16_t qty
					uint32_t price 	
				
				
				}
			
				7732
				
			
			
				*/
			}
			else
			{
				printf("772F INCOMPLETE\n");
			}
			
			
			
			break;
		}
		
		
		case 0x7600:
		{
			printf("Create Guild!\n");
			uint8_t uRes[] = {0xde,0xad};
			sendPacket30(uRes,sizeof(uRes),0x7601);
			
			
			
			//return guildID?
			
			/*
			struct
			{
				char *guildName
				char *guildComment
				uint8_t guildEmblem[0x212];	
				
				
				
				
				
				
				
				
			}
		
			
			
			
			
			
			
			
			*/
			
			
			break;	
		}
		
		
		
		
		case 0x7708:
		//Get GUILD_ITEM_LIST_members
		//gets item list for a specific guild. Why didn't they just re-use? oh. for member/public distinction?
		{
			uint8_t uRes[] = {0x00,0x01};
			sendPacket30(uRes,sizeof(uRes),0x7709);
			uint8_t uRes2[] = {0x00,0x00, 0x00,0x00, 0x00,0xff, 0x00,0x00,0x00,0x01};
			sendPacket30(uRes2,sizeof(uRes2),0x770a);
			
			
			
			
			break;
		}
		
		
		case 0x7728:
		{
			//enter guild item donation, I guess it's just an ack
			uint8_t uRes[] = {0x00,0x00};
			sendPacket30(uRes,sizeof(uRes),0x7729);
			
			
			
			
			break;
		}
		
		
		case 0x7702:
		{
			//GUILD_DONATE_ITEM
			uint8_t uRes[] = {0x00,0x01};
			sendPacket30(uRes,sizeof(uRes),0x7704);
			//return success, 1 item donated...
			
			
			
			
			break;
		}
		
		case 0x789c:
		{
			//get guild info after creation
			//arg is the guildID
			printf("Get Guild Info(Post Creation REQ)!\n");
			//uint16_t gID = ntohs(*(uint16_t*)(arg));
			
			
			
			//uint8_t uRes[] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
			
			
			//                 [0]        [1]        [2]          [3       ]  [5      ]  [7      ]  [9      ]  [11     ]  [13     ]  [15     ]                      [guild emblem?]   
			uint8_t uRes[]  = {0x30,0x00, 0x31,0x00, 0x32, 0x00,   0x00,0x01, 0x00,0x02, 0x00,0x03, 0x00,0x04, 0x00,0x05, 0x00,0x06, 0x00,0x07,  0x00,0x08, 0x00,0x00,0x00,0x09, 0x00,0x00,0x00,0x0a, 0x00,0x00,0x00,0x0b, 0x00,0x00,0x00,0x0c,    0x53,0x45,0x39,0x46,0x54,0x55,0x49,0x77,0x4D,0x41,0x41,0x41,0x41,0x41,0x41,0x41,0x67,0x49,0x43,0x41,0x41,0x49,0x43,0x41,0x67,0x41,0x43,0x41,0x67,0x49,0x41,0x41,0x67,0x49,0x43,0x41,0x41,0x41,0x3D,0x3D,0x00,  0x0d,0x0d, 0x0e,0x0e, 0x0f,0x0f, 0x10, 0x10, 0x12,0x12, 0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x20};
		
			sendPacket30(uRes,sizeof(uRes),0x789d);
			
		
		
		/*	
		struct	
		{
			char *unk		//guild name?
			char *unk         //guild comment?
			char *unk        //guild master?
			uint16_t unknown1; //3
			uint16_t unknown2; //5
			uint16_t unknown3; //7
			uint16_t unknown4; //9
			uint16_t unknown5; //11
			uint16_t unknown6; //13
			uint16_t unknown7; //15
			uint16_t unknown8; //??
			uint32_t unknown9; //???
			uint32_t unknown10
			uint32_t unknown11
			uint32_t unknown12
		
		}
		
		{
			char *guildName
			char *establishedDate
			char *guildMaster
			//membership
			uint16_t membersTotal;
			uint16_t numTwinBlades;
			uint16_t numBladeMasters;
			uint16_t numHeavyBlades;
			uint16_t numHeavyAxes;
			uint16_t numLongArms;
			uint16_t numWaveMasters;
			uint16_t averageLevel;
			//guild assets
			uint32_t goldCoins;
			uint32_t silverCoins;
			uint32_t copperCoins;
			uint32_t GP;
			//otherShit
			char* guildComment
				
		
		
		
		
		
		
		
		
		
		
		
		*/	
		break;	
			
		}
		//7610 get guild member list?
		
		
		case 0x7610:
		//OPCODE_DATA_GUILD_GET_MEMBER_LIST				0x7610
		//OPCODE_DATA_GUILD_GET_MEMBER_LIST_NUMCAT		 0x7611
		//OPCODE_DATA_GUILD_GET_MEMBER_LIST_NUMCAT
		{
			// Minimal Argument Size
			if (aSize >= 2)
			{
				uint16_t cID = ntohs(*(uint16_t*)(arg));
			
				//arg is category, ie, sort by. So you're going to have to keep track of which guild the user entered...
				//uint8_t uRes[] = {0x00,0x00};
				//sendPacket30(uRes,sizeof(uRes),0x7612);			
				printf("Get Guild Member List! Cat=%u",cID);	
			
			
				if(cID == 0x0)
				{
					uint8_t uRes[] = {0x00,0x01};
					uint8_t uRes2[] = {0x00,0x01, 0x30,0x30,0x00};
					sendPacket30(uRes,sizeof(uRes),0x7611);
					sendPacket30(uRes2,sizeof(uRes2),0x7613);
				}
				else
				{
					uint8_t uRes[] = {0x00,0x01};
					//				[name]          [unk] [level   ] [greeting           ]  [OSt]  [Model Details    ] 
					uint8_t uRes2[] = {0x31,0x31,0x00,0x01, 0x00,0x10, 0x32, 0x32,0x32,0x00,  0x00,  0x00,0x00,0x00,0x00, 0x02,0x00,0x00};
					sendPacket30(uRes,sizeof(uRes),0x7614);
					sendPacket30(uRes2,sizeof(uRes2),0x7615);
								
										
				}
			}
			else
			{
				printf("7610 INCOMPLETE\n");
			}
		/*
		0x7611 numCat
		struct
		{
			uint16_t numCat
		}
		
		0x7612 error
			//just displays "FAILED TO GET MENU" error.
		
		0x7613 cat
		struct
		{
			uint16_t catNum
			char *catName
		}
		
		0x7614 numEnty
		struct
		{
			uint16_t numEntry
		}
		
		0x7615 entry
		struct
		{
			char *pcName
			uint8_t class?
			uint16_t level?
			char *greeting
			uint8_t onlineStatus
				//00 = offline
				//01 = online
			uint32_t modelDetails
			uint8_t membershipStatus		
				//00 = member
				//01 = master
						
		*/	
		break;	
		}
		
		
		case 0x770c:
		//OPCODE_DATA_GUILD_SHOP_PURCHASE = 		   0x770c
		//OPCODE_DATA_GUILD_SHOP_PURCHASE_RESULT = 	0x770d
		{
			//buy item from guild shop
			printf("BUYING ITEM FROM GUILD SHOP!\n");
			uint8_t uRes[] = {0x00,0x62};
			sendPacket30(uRes,sizeof(uRes),0x770d);
			//returns number of items actually purchased. game WILL subtract money accordingly. means no BOGO.	
			
			
			/*
			0x770d
			struct
			{
				uint16_t shopID
				uint16_t itemCategory
				uint16_t itemIndex
				uint16_t qty
				uint32_t price	
				
			}
			
			
			
			*/
			
			
			
			break;
		}
		
		//772c get guild info?
		case OPCODE_DATA_MAIL_SEND:
		{
			printf("RECEIVED DATA_MAIL_SEND\n");
			uint8_t uRes[] = {0x00,0x00};
			printf("Sending MAIL_SEND_OK\n");
			sendPacket30(uRes, sizeof(uRes),OPCODE_DATA_MAIL_SEND_OK);
			
			
			break;
		}
						
								
												
		case OPCODE_DATA_LOGON_REPEAT:
		{
			switch (this->clientType)
			{
				case CLIENTTYPE_GAME:
				{
					printf("GAME CLIENT LOGGING IN!\n");
					break;
				}
				
				case CLIENTTYPE_AREASERVER:
				{
					printf("AREA SERVER LOGGING IN!\n");

					uint8_t uRes[] = {0x02,0x10};
					sendPacket30(uRes,sizeof(uRes),0x7001);
					break;					
				}	
				
				
				default:
				{
					printf("UNKNOWN CLIENT TYPE LOGGING ON!\n");
					break;
				}
			}
		
			printf("Recieved DATA_LOGON_REPEAT\n");
								
			break;								
		}
							
		default:
		{
			printf("NOT SURE HOW TO PROCEED...\n");	
			break;							
		}						
	}
}

/**
 * Wraps Data into a HTTP GET Response Packet and sends it
 * @param buffer HTTP Page Content (usually text)
 * @param bufferLength HTTP Page Content Length (in Bytes)
 * @param contentType HTTP Content Mimetype (ex. "text/html")
 * @return Result
 */
bool Client::sendHTTP(char * buffer, uint32_t bufferLength, char * contentType)
{
	// Result
	bool result = true;

	// Send Progress Meter
	int sentData = 0;
	
	// Craft HTTP Header
	char httpHeader[512];
	sprintf(httpHeader, "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: %u\r\nContent-Type: %s\r\n\r\n", bufferLength, contentType);

	// Send Header Data
	while (result && sentData < (int)strlen(httpHeader))
	{
		// Send Data
		int sendResult = send(socket, httpHeader + sentData, strlen(httpHeader) - sentData, MSG_NOSIGNAL);

		// Sent Data
		if (sendResult > 0)
		{
			// Accumulate Progress
			sentData += sendResult;
		}

		// Clean Disconnect
		else if (sendResult == 0)
		{
			// Set Result
			result = false;
		}

		// TX Buffer is full
		else if (errno == EAGAIN || errno == EWOULDBLOCK)
		{
			// Wait 1ms then retry
			usleep(1000);
		}

		// Unclean Disconnect
		else
		{
			// Set Result
			result = false;
		}
	}

	// Reset Progress Meter
	sentData = 0;

	// Send Body Data
	while (result && sentData < (int)bufferLength)
	{
		// Send Data
		int sendResult = send(socket, buffer + sentData, bufferLength - sentData, MSG_NOSIGNAL);

		// Sent Data
		if (sendResult > 0)
		{
			// Accumulate Progress
			sentData += sendResult;
		}

		// Clean Disconnect
		else if (sendResult == 0)
		{
			// Set Result
			result = false;
		}

		// TX Buffer is full
		else if (errno == EAGAIN || errno == EWOULDBLOCK)
		{
			// Wait 1ms then retry
			usleep(1000);
		}

		// Unclean Disconnect
		else
		{
			// Set Result
			result = false;
		}
	}

	// Error occured
	if (!result)
	{
		// Log Error
		printf("A HTTP Transmission Error occured!\n");
	}

	// Return Result
	return result;
}

/**
 * Wraps a static htdocs stored Image into a HTTP Get Response Packet and sends it
 * @param fileName Virtual Filesystem Filename
 * @return Result
 */
bool Client::sendHTTPImage(const char * fileName)
{
	// Result
	bool result = true;

	// Allocate File Path Memory
	char filePath[512];
	memset(filePath, 0, sizeof(filePath));

	// Party Face Icon requested
	if (strncmp(fileName, "xf", strlen("xf")) == 0)
	{
		// Create File Path
		snprintf(filePath, sizeof(filePath) - 1, "htdocs/images/party/%s", fileName);
	}

	// Friendlist Portrait requested
	else if (strncmp(fileName, "xp", strlen("xp")) == 0)
	{
		// Create File Path
		snprintf(filePath, sizeof(filePath) - 1, "htdocs/images/portraits/%s", fileName);
	}

	// Unknown Image Type requested
	else
	{
		// Send Warning to User
		char * warning = (char *)"Unknown Image Type requested!";
		sendHTTP(warning, strlen(warning), (char *)"text/plain");
		result = false;
	}

	// No error just yet
	if (result)
	{
		// Open File
		FILE * fd = fopen(filePath, "rb");

		// File opened
		if (fd != NULL)
		{
			// Calculate File Size
			fseek(fd, 0, SEEK_END);
			uint32_t size = (uint32_t)ftell(fd);
			fseek(fd, 0, SEEK_SET);

			// Allocate File Content Memory
			uint8_t * fileContent = new uint8_t[size];

			// Load File Content
			if (fread(fileContent, size, 1, fd) == 1)
			{
				// Send File Content
				result = sendHTTP((char *)fileContent, size, (char *)"image/png");
			}

			// File couldn't be read
			else
			{
				// Send Warning to User
				char * warning = (char *)"Image couldn't be read!";
				sendHTTP(warning, strlen(warning), (char *)"text/plain");
				result = false;
			}

			// Free File Content Memory
			delete [] fileContent;

			// Close File
			fclose(fd);
		}

		// File not found
		else
		{
			// Send Warning to User
			char * warning = (char *)"Image couldn't be found!";
			sendHTTP(warning, strlen(warning), (char *)"text/plain");
			result = false;
		}
	}

	// Return Result
	return result;
}

/**
 * Process accumulated Packets on the RX Buffer
 * @return Processing Result
 */
bool Client::ProcessRXBuffer()
{
	// Webclient Processing
	if (this->clientType == CLIENTTYPE_WEBCLIENT)
	{
		// Yeah it's a goto mark, bite me.
		webClientHandler:

		// Update Heartbeat for HTTP Connections
		this->lastHeartbeat = time(NULL);

		// Minimum HTTP Request Length
		uint32_t minHTTPReqLength = strlen("GET / HTTP/1.1\r\n\r\n");

		// Incomplete HTTP Request
		if (this->rxBufferPosition < minHTTPReqLength)
			return true;

		// Incomplete HTTP Request (no newline suffix yet)
		if (strncmp((char *)(this->rxBuffer + this->rxBufferPosition - strlen("\r\n\r\n")), "\r\n\r\n", strlen("\r\n\r\n")) != 0)
			return true;
		
		// Terminating HTTP Request String not possible (buffer overrun check)
		if (this->rxBufferPosition == this->rxBufferLength)
			return false;

		// Terminate HTTP Request String
		this->rxBuffer[this->rxBufferPosition + 1] = 0;

		// Figure out what the user wants
		char * requestedPage = NULL;
		for (uint32_t i = 0; i < this->rxBufferPosition; i++)
		{
			// Found GET Line
			if (strncmp((char *)(this->rxBuffer + i), "GET /", strlen("GET /")) == 0)
			{
				// Isolate Path Variable
				char * path = (char *)(this->rxBuffer + i + strlen("GET /"));

				// Terminate Path Variable
				uint32_t j = 0;
				while (strncmp(path + j, " ", strlen(" ")) != 0) j++;
				path[j] = 0;

				// Save Path Variable Reference
				requestedPage = path;

				// Stop Buffer Scan
				break;
			}
		}

		// Hacking Attempt or non-get request (either way, we are not interested in handling it)
		if (requestedPage == NULL)
			return false;

		// Server Status requested
		if (requestedPage[0] == 0)
		{
			// Fetch Area Server List from Server Singleton
			std::list<AreaServer *> * areaServer = Server::getInstance()->GetAreaServerList();

			// Fetch Client List from Server Singleton
			std::list<Client *> * clients = Server::getInstance()->GetClientList();

			// Zero Player Bit
			bool noPlayersFound = true;

			// Calculate the Server Status Buffer Size
			uint32_t serverStatusBufferSize = 524288 + 256 * (clients->size() + areaServer->size());

			// Allocate & Render Server Status Information Text
			char * serverStatus = new char[serverStatusBufferSize];
			memset(serverStatus, 0, serverStatusBufferSize);

			// Render Server Status Page Header
			snprintf(serverStatus, serverStatusBufferSize - 1,
				"<html>\n"
				"<head>\n"
				"<meta charset=\"shift-jis\" />\n"
				"<title>.hack//fragment Server Status</title>\n"
				"<style type=\"text/css\">\n"
				"div.pagetitle { font-size:18pt }\n"
				"div.pagesubtitle { font-size:9pt; padding-left:0.3em; margin-bottom:1em }\n"
				"div.sectiontitle { font-size:10pt; font-weight:bold; padding-left:0.5em; margin-top:0.5em }\n"
				"div.textline { font-size:9pt; margin-left:2em }\n"
				"div.characteravatar { border-style:solid; border-width:1px; border-color:black }\n"
				"div.characterinfobox { padding:0.5em }\n"
				"div.charactername { font-size:10pt; font-weight:bold }\n"
				"div.characterclass { font-size:9pt; font-weight:bold; margin-bottom: 0.1em }\n"
				"div.characterstatus { font-size:9pt; font-weight:bold }\n"
				"span.characterhp { color:green }\n"
				"span.charactersp { color:blue }\n"
				"span.charactergp { color:gold }\n"
				"div.characterdungeons { font-size:9pt; font-weight:bold }\n"
				"div.charactermessagebox { margin-left:0.5em }\n"
				"div.charactermessageheader { font-size:8pt; font-weight:bold }\n"
				"div.charactermessage { border-style:solid; border-width:1px; padding:0.5em; font-size:9pt }\n"
				"</style>\n"
				"</head>\n"
				"<body>\n"
				"<div class=\"pagetitle\">.hack//fragment Server</div>\n"
				"<div class=\"pagesubtitle\">Revision: %s</div>\n"
				"<div class=\"sectiontitle\">Available Server</div>\n", GIT_VERSION);

			// Area Server List is empty
			if (areaServer->size() == 0)
			{
				// Render None Text
				snprintf(serverStatus + strlen(serverStatus), serverStatusBufferSize - strlen(serverStatus) - 1, "<div class=\"textline\">None</div>\n");
			}

			// Area Server List contains at least one server
			else
			{
				// Iterate Area Server
				for(std::list<AreaServer *>::iterator it = areaServer->begin(); it != areaServer->end(); it++)
				{
					// Fetch Area Server Object
					AreaServer * server = *it;

					// Output Server Information
					snprintf(serverStatus + strlen(serverStatus), serverStatusBufferSize - strlen(serverStatus) - 1, "<div class=\"textline\">%s - Level %u - %s - %u Player</div>\n", server->GetServerName(), server->GetServerLevel(), server->GetServerStatusText(), server->GetPlayerCount());
				}
			}

			// Render Player Header
			snprintf(serverStatus + strlen(serverStatus), serverStatusBufferSize - strlen(serverStatus) - 1, "<div class=\"sectiontitle\">Available Player</div>\n");

			// Iterate Clients
			for(std::list<Client *>::iterator it = clients->begin(); it != clients->end(); it++)
			{
				// Fetch Client Object
				Client * client = *it;

				// Ignore Non-PS2 Clients
				if (client->GetClientType() == CLIENTTYPE_GAME)
				{
					// Client is missing the minimal amount of display data
					if (client->GetDiskID() == NULL || client->GetSaveID() == NULL) continue;

					// Client is missing character display data
					if (client->GetCharacterSaveID() == NULL || client->GetCharacterName() == NULL) continue;

					// First Player we found
					if (noPlayersFound)
					{
						// Render Table Header
						snprintf(serverStatus + strlen(serverStatus), serverStatusBufferSize - strlen(serverStatus) - 1, "<table>\n");

						// Erase Zero Player Bit
						noPlayersFound = false;
					}

					// Output Client Information
					snprintf(serverStatus + strlen(serverStatus), serverStatusBufferSize - strlen(serverStatus) - 1,
						"<tr>\n"
						"<td>\n"
						"<div class=\"characteravatar\"><img src=\"images/%s.png\" width=\"60\" height=\"64\" /></div>\n"
						"</td>\n"
						"<td>\n"
						"<div class=\"characterinfobox\">\n"
						"<div class=\"charactername\">%s</div>\n"
						"<div class=\"characterclass\">Level %u %s</div>\n"
						"<div class=\"characterstatus\"><span class=\"characterhp\">HP %u</span> / <span class=\"charactersp\">SP %u</span> / <span class=\"charactergp\">GP %lld</span></div>\n"
						"<div class=\"characterdungeons\">Treasures found: %u online, %u offline</div>\n"
						"</div>\n"
						"</td>\n"
						"<td>\n"
						"<div class=\"charactermessagebox\">\n"
						"<div class=\"charactermessageheader\">MESSAGE</div>\n"
						"<div class=\"charactermessage\">%s</div>\n"
						"<div>\n"
						"</td>\n"
						"</tr>\n", client->GetCharacterModelPortrait(false), client->GetCharacterName(), client->GetCharacterLevel(), client->GetCharacterClassName(), client->GetCharacterHP(), client->GetCharacterSP(), client->GetCharacterGP(), client->GetGodStatueCounter(true), client->GetGodStatueCounter(false), client->GetCharacterGreeting(true));
				}
			}

			// No Players found
			if (noPlayersFound)
			{
				// Render None Text
				snprintf(serverStatus + strlen(serverStatus), serverStatusBufferSize - strlen(serverStatus) - 1, "<div class=\"textline\">None</div>\n");
			}

			// Found at least one player
			else
			{
				// Render Table Footer
				snprintf(serverStatus + strlen(serverStatus), serverStatusBufferSize - strlen(serverStatus) - 1, "</table>\n");
			}

			// Render Server Status Page Footer
			snprintf(serverStatus + strlen(serverStatus), serverStatusBufferSize - strlen(serverStatus) - 1, "</body>\n</html>");

			// Output Server Status information via HTTP
			sendHTTP(serverStatus, strlen(serverStatus), (char *)"text/html");

			// Free Memory
			delete [] serverStatus;

			// Notify Administrator
			printf("User requested Server Status via HTTP\n");
		}

		// Static Image requested
		else if (strncmp(requestedPage, "images/", strlen("images/")) == 0)
		{
			// Fetch Image Filename
			char * fileName = requestedPage + strlen("images/");

			// Count Dots in Filename
			uint32_t dotCount = 0;
			for (uint32_t i = 0; i < strlen(fileName); i++)
			{
				if (fileName[i] == '.') dotCount++;
			}

			// Hacking Attempt detected
			if (dotCount > 1 || strlen(fileName) < strlen("a.png") || strcmp(fileName + strlen(fileName) - strlen(".png"), ".png") != 0)
				return false;

			// Send Static Image via HTTP
			sendHTTPImage(fileName);
		}

		// Discard Data
		MoveRXPointer(this->rxBufferPosition * (-1));

		// Disconnect Webclients after their request to stop lingering Keep-Alives
		return false;
	}

	// Game / Area Server / Undefined Processing
	else
	{
		// Data available in RX Buffer
		while(this->rxBufferPosition > 2)
		{
			// Check for "GE" in "GET" HTTP Command
			if (strncmp((char *)this->rxBuffer, "GE", 2) == 0)
			{
				// Blindly assume that this is a Webclient for now (I really don't want to listen on a separate port for this)
				this->clientType = CLIENTTYPE_WEBCLIENT;

				// Notify Administrator
				printf("Switched Client into Webclient Mode!\n");

				// Resume Handling in the Webclient Handler (just in case all the data came in in one TCP recv call)
				goto webClientHandler;
			}

			// Extract Packet Length
			uint16_t packetLength = ntohs(*(uint16_t *)this->rxBuffer);

			// Packet available in RX Buffer
			if(this->rxBufferPosition >= (sizeof(uint16_t) + packetLength))
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
					uint8_t decryptedPacket[0x500a];
					uint32_t decryptedPacketLength = sizeof(decryptedPacket);
					crypto[KEY_CLIENT]->Decrypt(encryptedPacket, packetLength, decryptedPacket, &decryptedPacketLength);

					// Output Decrypted Data
					printf("Decrypted Data: ");
					for(uint32_t i = 0; i < decryptedPacketLength; i++)
					{
						printf("0x%02X", decryptedPacket[i]);
						if(i != decryptedPacketLength - 1) printf(", ");
					}
					printf("\n");
				

					// Invalid Packet Length (body is never < 4)
					if(decryptedPacketLength < 4)
					{
						printf("Received packet with an invalid body length of %u bytes!\n", decryptedPacketLength);
						return false;
					}

					// Read Packet Checksum
					uint16_t packetChecksum = ntohs(*(uint16_t *)decryptedPacket);

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
							// Calculate Checksum
							uint16_t calculatedPacketChecksum = Crypto::Checksum(decryptedPacket + sizeof(uint16_t), decryptedPacketLength - sizeof(uint16_t));

							// Invalid Checksum
							if(packetChecksum != calculatedPacketChecksum)
							{
								printf("Received packet failed the checksum test (0x%04X != 0x%04X)!\n", packetChecksum, calculatedPacketChecksum);
								return false;
							}

							// Read Key Length from Packet
							uint16_t keyLength = ntohs(*(uint16_t *)(decryptedPacket + sizeof(uint16_t)));
						
							// Read Key from Packet
							uint8_t * key = decryptedPacket + sizeof(uint16_t) * 2;
						
							// Key Length out of bounds
							if(keyLength == 0 || keyLength > decryptedPacketLength - (sizeof(uint16_t) * 2))
							{
								printf("Received key length (%u > %u) exceeds the packet boundaries!\n", keyLength, (uint32_t)(decryptedPacketLength - sizeof(uint16_t) * 2));
								return false;
							}
						
							// Key Length over maximum allowed length
							if(keyLength > 16)
							{
								printf("Received key length exceeds the allowed maximum key length (%u > 16)!\n", keyLength);
								return false;
							}
						
							// Create Cryptography Objects
							crypto[KEY_CLIENT_PENDING] = new Crypto(key, keyLength);
							uint8_t randKey[16];
							for(uint32_t i = 0; i < sizeof(randKey); i++) randKey[i] = rand() % 256;
							crypto[KEY_SERVER_PENDING] = new Crypto(randKey, sizeof(randKey));
						

							// Output Random Key
							printf("Generated Random Key:\n");
							for(uint32_t i = 0; i < sizeof(randKey); i++)
							{
								printf("0x%02X", randKey[i]);
								if(i != sizeof(randKey) - 1) printf(", ");
							}
							printf("\n");

							// Allocate Response Buffer
							uint8_t response[52] = {0};
							uint8_t decryptedResponse[48] = {0};
						
							// Cast Fields
							uint16_t * packetLengthField = (uint16_t *)response;
							uint16_t * packetOpcodeField = &packetLengthField[1];
							uint8_t * packetPayloadField = (uint8_t *)&packetOpcodeField[1];
							uint16_t * checksumField = (uint16_t *)decryptedResponse;
							uint16_t * keyLengthField1 = &checksumField[1];
							uint8_t * keyField1 = (uint8_t *)&keyLengthField1[1];
							uint16_t * keyLengthField2 = (uint16_t *)(keyField1 + keyLength);
							uint8_t * keyField2 = (uint8_t *)&keyLengthField2[1];
							uint32_t * defaultSeg = (uint32_t *)(keyField2 + keyLength);
						
							// Write Static Data
							*packetLengthField = htons(sizeof(response) - sizeof(*packetLengthField));
							*packetOpcodeField = htons(OPCODE_KEY_EXCHANGE_RESPONSE);
							*keyLengthField1 = htons(keyLength);
							*keyLengthField2 = htons(sizeof(randKey));
							*defaultSeg = htonl(this->segServer);
												
																																										
							// Write Secret Keys
							memcpy(keyField1, key, keyLength);
							memcpy(keyField2, randKey, sizeof(randKey));
						
							// Calculate Checksum
							*checksumField = htons(Crypto::Checksum((uint8_t *)&checksumField[1], sizeof(decryptedResponse) - sizeof(*checksumField)));
																							
							// Encrypt Response
							uint32_t packetPayloadFieldSize = sizeof(response) - sizeof(*packetLengthField) - sizeof(*packetOpcodeField);
							crypto[KEY_SERVER]->Encrypt(decryptedResponse, sizeof(decryptedResponse), packetPayloadField, &packetPayloadFieldSize);

							// Send Response
							send(socket, response, sizeof(response), MSG_NOSIGNAL);

							// Log Event
							printf("Key Exchange finished!\n");

							// Break Switch
							break;
						}

						// Key Exchange Acknowledgment
						case OPCODE_KEY_EXCHANGE_ACKNOWLEDGMENT:
						{
							// Pending Keys weren't set yet
							if(crypto[KEY_CLIENT_PENDING] == NULL || crypto[KEY_SERVER_PENDING] == NULL)
							{
								printf("There are no pending keys to check the acknowledgment against!\n");
								return false;
							}

							// Read Key Length from Packet
							uint16_t keyLength = ntohs(*(uint16_t *)(decryptedPacket + sizeof(uint16_t)));

							// Read Key from Packet
							uint8_t * key = decryptedPacket + sizeof(uint16_t) * 2;

							// Key Length out of bounds
							if(keyLength == 0 || keyLength > decryptedPacketLength - (sizeof(uint16_t) * 2))
							{
								printf("Received key length (%u > %u) exceeds the packet boundaries!\n", keyLength, (uint32_t)(decryptedPacketLength - sizeof(uint16_t) * 2));
								return false;
							}

							// Calculate Checksum
							uint16_t calculatedPacketChecksum = Crypto::Checksum(decryptedPacket + sizeof(uint16_t), keyLength + sizeof(uint16_t));

							// Invalid Checksum
							if(packetChecksum != calculatedPacketChecksum)
							{
								printf("Received packet failed the checksum test (0x%04X != 0x%04X)!\n", packetChecksum, calculatedPacketChecksum);
								return false;
							}

							// Key Length over maximum allowed length
							if(keyLength > 16)
							{
								printf("Received key length exceeds the allowed maximum key length (%u > 16)!\n", keyLength);
								return false;
							}

							// Key Lengths don't match
							if(crypto[KEY_SERVER_PENDING]->GetKeyLength() != keyLength)
							{
								printf("The server and acknowledgment key lengths don't match!\n");
								return false;
							}

							// Keys don't match
							if(memcmp(crypto[KEY_SERVER_PENDING]->GetKey(), key, keyLength) != 0)
							{
								printf("The server and acknowledgment keys don't match!\n");
								return false;
							}

							// Free Memory of previous Crypto Handler
							delete crypto[KEY_CLIENT];
							delete crypto[KEY_SERVER];

							// Activate Keys
							crypto[KEY_CLIENT] = crypto[KEY_CLIENT_PENDING];
							crypto[KEY_SERVER] = crypto[KEY_SERVER_PENDING];
							crypto[KEY_CLIENT_PENDING] = NULL;
							crypto[KEY_SERVER_PENDING] = NULL;

							// Debug Output
							printf("Key Exchange Acknowledgment was successful!\n");

							// Break Switch
							break;
						}

						// Data Packet
						case OPCODE_DATA:
						{
							// Log Event
							printf("Received Data Packet!\n");

							// Argument Length Parameter missing
							if(decryptedPacketLength < (sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint16_t)))
							{
								printf("The data argument length is missing!\n");
								return false;
							}

							// Extract Client Segment Number
							uint32_t newSeg = ntohl(*(uint32_t *)(decryptedPacket + sizeof(uint16_t)));

							// Invalid Segment Number
							if (newSeg <= this->segClient)
							{
								printf("The Client's Segment Number was less than or equal to the last one (%d <= %d)!", newSeg, this->segClient);
								return false;
							}

							// Extract Argument Length
							uint16_t argumentLength = ntohs(*(uint16_t *)(decryptedPacket + sizeof(uint16_t) + sizeof(uint32_t)));

							// Calculate Checksum Base Length
							uint32_t checksumBaseLength = sizeof(uint32_t) + sizeof(uint16_t) + argumentLength;

							//Extract internal Opcode...
							uint16_t internalOpcode = ntohs(*(uint16_t *)(decryptedPacket + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint16_t)));

							// Argument Parameter missing
							if(decryptedPacketLength < (sizeof(uint16_t) + checksumBaseLength))
							{
								printf("The data argument is missing!\n");
								return false;
							}

							// Calculate Checksum
							uint16_t calculatedPacketChecksum = Crypto::Checksum(decryptedPacket + sizeof(uint16_t), checksumBaseLength);

							// Invalid Checksum
							if(packetChecksum != calculatedPacketChecksum)
							{
								printf("Received packet failed the checksum test (0x%04X != 0x%04X)!\n", packetChecksum, calculatedPacketChecksum);
								return false;
							}

							// Extract Argument
							uint8_t * argument = decryptedPacket + sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t);

							// Output Client Segment Number
							printf("Client Segment: 0x%02X\n",newSeg);

							// Update Client Segment Number in Object
							this->segClient = newSeg;
							
							// Output Internal Opcode
							printf("Internal Opcode: 0x%02X\n", internalOpcode);

							// Output Argument Data
							argumentLength -= sizeof(uint16_t);
							printf("Argument Data:\n");
							for(uint32_t i = 0; i < argumentLength; i++)
							{
								printf("0x%02X", argument[i]);
								if(i < (uint32_t)(argumentLength - 1)) printf(", ");
							}
							printf("\n");

							// Append Log to Logfile
							if(this->enableLogging)
							{
								char lBuff[16];
								sprintf(lBuff,"%02X",internalOpcode);
								this->logFile << "Received 0x30_0x" << lBuff << " ";
								sprintf(lBuff,"0x%02X",decryptedPacketLength);
								this->logFile << lBuff << " bytes of data\n\t";
								for(uint32_t i = 0; i < decryptedPacketLength; i++)
								{
									sprintf(lBuff,"%02X ",decryptedPacket[i]);
									this->logFile << lBuff;
								}
								this->logFile << "\n";
							}

							// Process 0x30 Data Packet Contents
							processPacket30((uint8_t*)argument, (uint16_t)argumentLength, (uint16_t)internalOpcode);						

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
						case OPCODE_KEY_EXCHANGE_RESPONSE:
						case OPCODE_KEY_EXCHANGE_ACKNOWLEDGMENT:
						case OPCODE_DATA:
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
	}

	// Keep Connection alive
	return true;
}

/**
 * Returns the Client Type
 * @return Client Type (or -1 if undefined)
 */
int Client::GetClientType()
{
	// Return Client Type
	return this->clientType != 0 ? this->clientType : -1;
}

/**
 * Returns the Disk ID of the Client (as a 64B null terminated hexstring)
 * @return Disk ID (or NULL if undefined)
 */
const char * Client::GetDiskID()
{
	// Return Disk ID
	return this->diskID[0] != 0 ? this->diskID : NULL;
}

/**
 * Returns the Disk ID of the Client (as a 32B array)
 * @return Disk ID (or NULL if undefined)
 */
const uint8_t * Client::GetDiskIDBytes()
{
	// Static Result Buffer
	static uint8_t idb8[32];

	// Scan Buffer
	uint32_t idb[32];

	// Disk ID not set
	if (this->diskID[0] == 0) return NULL;

	// Parse Disk ID
	if (sscanf(this->diskID, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", &idb[0], &idb[1], &idb[2], &idb[3], &idb[4], &idb[5], &idb[6], &idb[7], &idb[8], &idb[9], &idb[10], &idb[11], &idb[12], &idb[13], &idb[14], &idb[15], &idb[16], &idb[17], &idb[18], &idb[19], &idb[20], &idb[21], &idb[22], &idb[23], &idb[24], &idb[25], &idb[26], &idb[27], &idb[28], &idb[29], &idb[30], &idb[31]) < 32)
		return NULL;

	// Convert to Byte Buffer
	for (uint32_t i = 0; i < 32; i++)
	{
		// Mask Data
		idb8[i] = idb[i] & 0xFF;
	}

	// Return Disk ID
	return idb8;
}

/**
 * Returns the System Save ID of the Client (as a 20B null terminated hexstring)
 * @return System Save ID (or NULL if undefined)
 */
const char * Client::GetSaveID()
{
	// Return Save ID
	return this->saveID[0] != 0 ? this->saveID : NULL;
}

/**
 * Returns the System Save ID of the Client (as a 10B array)
 * @return System Save ID (or NULL if undefined)
 */
const uint8_t * Client::GetSaveIDBytes()
{
	// Static Result Buffer
	static uint8_t idb8[10];

	// Scan Buffer
	uint32_t idb[10];

	// Disk ID not set
	if (this->saveID[0] == 0) return NULL;

	// Parse Disk ID
	if (sscanf(this->saveID, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", &idb[0], &idb[1], &idb[2], &idb[3], &idb[4], &idb[5], &idb[6], &idb[7], &idb[8], &idb[9]) < 10)
		return NULL;

	// Convert to Byte Buffer
	for (uint32_t i = 0; i < 10; i++)
	{
		// Mask Data
		idb8[i] = idb[i] & 0xFF;
	}

	// Return Disk ID
	return idb8;
}

/**
 * Returns the Character Save ID of the Client (as a 20B null terminated hexstring)
 * @return Character Save ID (or NULL if undefined)
 */
const char * Client::GetCharacterSaveID()
{
	// Return Character Save ID
	return this->activeCharacterSaveID[0] != 0 ? this->activeCharacterSaveID : NULL;
}

/**
 * Returns the Character Save ID of the Client (as a 10B array)
 * @return Character Save ID (or NULL if undefined)
 */
const uint8_t * Client::GetCharacterSaveIDBytes()
{
	// Static Result Buffer
	static uint8_t idb8[10];

	// Scan Buffer
	uint32_t idb[10];

	// Disk ID not set
	if (this->activeCharacterSaveID[0] == 0) return NULL;

	// Parse Disk ID
	if (sscanf(this->activeCharacterSaveID, "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", &idb[0], &idb[1], &idb[2], &idb[3], &idb[4], &idb[5], &idb[6], &idb[7], &idb[8], &idb[9]) < 10)
		return NULL;

	// Convert to Byte Buffer
	for (uint32_t i = 0; i < 10; i++)
	{
		// Mask Data
		idb8[i] = idb[i] & 0xFF;
	}

	// Return Disk ID
	return idb8;
}

/**
 * Returns the Name of the logged in Character (inside of Lobby)
 * @return Character Name (or NULL if undetectable)
 */
const char * Client::GetCharacterName()
{
	// Return Character Name
	return this->activeCharacter[0] != 0 ? this->activeCharacter : NULL;
}

/**
 * Returns the Greeting Message of the logged in Character (inside of Lobby)
 * @param htmlSafe Should the text be HTML escaped?
 * @return Character Greeting (or NULL if undetectable)
 */
const char * Client::GetCharacterGreeting(bool htmlSafe)
{
	// Static HTML Escape Buffer
	static char html[4096];

	// Character isn't logged in yet
	if (this->activeCharacter[0] == 0) return NULL;

	// Normal Message requested
	if (!htmlSafe) return this->activeCharacterGreeting;

	// Clean Buffer
	memset(html, 0, sizeof(html));

	// Escape Text
	for (uint32_t i = 0; i < strlen(this->activeCharacterGreeting); i++)
	{
		// Fetch Character
		char c = this->activeCharacterGreeting[i];

		// Ampersand
		if (c == '&') snprintf(html + strlen(html), sizeof(html) - strlen(html) - 1, "&amp;");

		// Quotation Mark
		else if (c == '"') snprintf(html + strlen(html), sizeof(html) - strlen(html) - 1, "&quot;");

		// Single Quotation Mark
		else if (c == '\'') snprintf(html + strlen(html), sizeof(html) - strlen(html) - 1, "&#039;");

		// Smaller Than
		else if (c == '<') snprintf(html + strlen(html), sizeof(html) - strlen(html) - 1, "&lt;");

		// Greater Than
		else if (c == '>') snprintf(html + strlen(html), sizeof(html) - strlen(html) - 1, "&gt;");

		// Carriage Return
		else if (c == '\r') /* Skip */ ;

		// Linefeed
		else if (c == '\n') snprintf(html + strlen(html), sizeof(html) - strlen(html) - 1, "<br />");

		// Printable Sign
		else if ((sizeof(html) - strlen(html) - 1) > 0) html[strlen(html)] = c;
	}

	// Return HTML Escaped Text
	return html;
}

/**
 * Returns the Level of the logged in Character (inside of Lobby)
 * @return Character Level (or -1 if undetectable)
 */
int Client::GetCharacterLevel()
{
	// Return Character Level
	return this->activeCharacter[0] != 0 ? this->activeCharacterLevel : -1;
}

/**
 * Returns the numeric Class of the logged in Character (inside of Lobby)
 * @return Numeric Character Class (or -1 if undetectable)
 */
int Client::GetCharacterClass()
{
	// Return Character Class
	return (this->activeCharacter[0] != 0 && this->activeCharacterClass >= CLASS_TWINBLADE && this->activeCharacterClass <= CLASS_WAVEMASTER) ? this->activeCharacterClass : -1;
}

/**
 * Returns a human-readable Class Name of the logged in Character (inside of Lobby)
 * @return Character Class Name (or NULL if undetectable)
 */
const char * Client::GetCharacterClassName()
{
	// Fetch Character Class Index
	int index = GetCharacterClass();

	// Invalid Index
	if (index < CLASS_TWINBLADE || index > CLASS_WAVEMASTER) return NULL;

	// Return Character Class Name
	return classNames[index];
}

/**
 * Returns the Model Class of the logged in Character (inside of Lobby)
 * @return Model Class (or -1 if undetectable)
 */
char Client::GetCharacterModelClass()
{
	// Character not logged in
	if (GetCharacterName() == NULL) return -1;

	// Class Model Name Letters
	char classLetters[6] = { 't', 'b', 'h', 'a', 'l', 'w' };

	// Fetch Character Class Index
	int index = activeCharacterModel & 0x0F;

	// Invalid Index
	if (index < CLASS_TWINBLADE || index > CLASS_WAVEMASTER) return -1;

	// Return Class Model Name Letter
	return classLetters[index];
}

/**
 * Returns the Model Number of the logged in Character (inside of Lobby)
 * @return Model Number (or -1 if undetectable)
 */
char Client::GetCharacterModelNumber()
{
	// Character not logged in
	if (GetCharacterName() == NULL) return -1;

	// Return Character Model Number
	return (activeCharacterModel >> 4 & 0x0F) + 1;
}

/**
 * Returns the Model Type of the logged in Character (inside of Lobby)
 * @return Model Type (or -1 if undetectable)
 */
char Client::GetCharacterModelType()
{
	// Character not logged in
	if (GetCharacterName() == NULL) return -1;

	// Model Type Letters
	char typeLetters[9] = { 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i' };

	// Fetch Model Type Index
	int index = (activeCharacterModel >> 12) & 0x0F;

	// Invalid Index
	if (index < 0 || index > 8) return -1;

	// Return Model Type Letter
	return typeLetters[index];
}

/**
 * Returns the Color Code of the logged in Character (inside of Lobby)
 * @return Character Color Code (or NULL if undetectable)
 */
const char * Client::GetCharacterModelColorCode()
{
	// Character not logged in
	if (GetCharacterName() == NULL) return NULL;

	// Color Codes
	char * colorCodes[6] = { (char *)"rd", (char *)"bl", (char *)"yl", (char *)"gr", (char *)"br", (char *)"pp" };

	// Fetch Color Code Index
	int index = (activeCharacterModel >> 8) & 0x0F;

	// Invalid Index
	if (index < 0 || index > 5) return NULL;

	// Return Color Code
	return colorCodes[index];
}

/**
 * Returns the Character Portrait of the logged in Character (inside of Lobby)
 * @param rounded Return the rounded portrait?
 * @return Character Portrait (or NULL if undetectable)
 */
const char * Client::GetCharacterModelPortrait(bool rounded)
{
	// Static Result Buffer
	static int index = 0;
	static char name[2][32];

	// Fetch required Parameter
	char classLetter = GetCharacterModelClass();
	char modelNumber = GetCharacterModelNumber();
	char modelType = GetCharacterModelType();
	const char * colorCode = GetCharacterModelColorCode();

	// Character not logged in
	if (classLetter == -1 || modelNumber == -1 || modelType == -1 || colorCode == NULL)
		return NULL;

	// Render Character Portrait Filename
	sprintf(name[index], (rounded ? "xf%c%d%c_%s" : "xp%c%d%c_%s"), classLetter, modelNumber, modelType, colorCode);

	// Pick Result Buffer
	char * result = name[index];

	// Switch Index for next call
	index = index == 0 ? 1 : 0;

	// Return Character Portrait Filename
	return result;
}

/**
 * Returns the Height of the logged in Character (inside of Lobby)
 * @return Character Height (or -1 if undetectable)
 */
int Client::GetCharacterModelHeight()
{
	// Fetch Model Type
	char modelType = GetCharacterModelType();

	// Invalid Model Type
	if (modelType < 'a' || modelType > 'i') return -1;

	// Short Height
	if (modelType >= 'a' && modelType <= 'c') return HEIGHT_SHORT;

	// Normal Height
	if (modelType >= 'd' && modelType <= 'f') return HEIGHT_NORMAL;

	// Tall Height
	return HEIGHT_TALL;
}

/**
 * Returns the human-readable display of the logged in Character's Height (inside of Lobby)
 * @return Character Height (or NULL if undetectable)
 */
const char * Client::GetCharacterModelHeightText()
{
	// Human-readable Heights
	char * heights[3] = {
		(char *)"Short",
		(char *)"Normal",
		(char *)"Tall"
	};

	// Get Model Height
	int height = GetCharacterModelHeight();

	// Invalid Model Height
	if (height < HEIGHT_SHORT || height > HEIGHT_TALL) return NULL;

	// Return Height
	return heights[height];
}

/**
 * Returns the Weight of the logged in Character (inside of Lobby)
 * @return Character Weight (or -1 if undetectable)
 */
int Client::GetCharacterModelWeight()
{
	// Fetch Model Type
	char modelType = GetCharacterModelType();

	// Invalid Model Type
	if (modelType < 'a' || modelType > 'i') return -1;

	// Thin Character
	if (modelType == 'a' || modelType == 'd' || modelType == 'g') return WEIGHT_ANOREXIC;

	// Normal Height
	if (modelType == 'b' || modelType == 'e' || modelType == 'h') return WEIGHT_NORMAL;

	// Tall Height
	return WEIGHT_OBESE;
}

/**
 * Returns the human-readable display of the logged in Character's Weight (inside of Lobby)
 * @return Character Weight (or NULL if undetectable)
 */
const char * Client::GetCharacterModelWeightText()
{
	// Human-readable Weights
	char * weights[3] = {
		(char *)"Anorexic",
		(char *)"Normal",
		(char *)"Obese"
	};

	// Get Model Weight
	int weight = GetCharacterModelWeight();

	// Invalid Model Weight
	if (weight < WEIGHT_ANOREXIC || weight > WEIGHT_OBESE) return NULL;

	// Return Weight
	return weights[weight];
}

/**
 * Returns the HP of the logged in Character (inside of Lobby)
 * @return Character HP (or -1 if undetectable)
 */
int Client::GetCharacterHP()
{
	// Character not logged in
	if (GetCharacterName() == NULL) return -1;

	// Return Character HP
	return this->activeCharacterHP;
}

/**
 * Returns the SP of the logged in Character (inside of Lobby)
 * @return Character SP (or -1 if undetectable)
 */
int Client::GetCharacterSP()
{
	// Character not logged in
	if (GetCharacterName() == NULL) return -1;

	// Return Character SP
	return this->activeCharacterSP;
}

/**
 * Returns the GP of the logged in Character (inside of Lobby)
 * @return Character GP (or -1 if undetectable)
 */
int64_t Client::GetCharacterGP()
{
	// Character not logged in
	if (GetCharacterName() == NULL) return -1;

	// Return Character GP
	return this->activeCharacterGP;
}

/**
 * Returns the number of Offline / Online Dungeons the logged in Character finished (inside of Lobby)
 * @param online Should the Online Counter be returned?
 * @return Offline Dungeon Counter
 */
int Client::GetGodStatueCounter(bool online)
{
	// Character not logged in
	if (GetCharacterName() == NULL) return -1;

	// Return Online Counter
	return online ? this->activeCharacterOnlineGodCounter : activeCharacterOfflineGodCounter;
}

/**
 * Returns the Anti Cheat Engine Evaluation Result
 * @return Is this player a cheater?
 */
bool Client::GetAntiCheatEngineResult()
{
	// TODO Add proper evaluation
	return false;
}

/**
 * Read Client Timeout Status
 * @return Timeout Status
 */
bool Client::IsTimedOut()
{
	// Calculate Delta Time
	double deltaTime = difftime(time(NULL), this->lastHeartbeat);

	// No Reaction in 30s
	return deltaTime >= 30;
}
