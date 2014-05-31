#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdlib.h>
#include "opcode.h"
#include "client.h"
#include <ctime>
#include "areaServer.h"
#include <list>
#include "ccsNewsImage.h"

// Area Server List
extern std::list<AreaServer *> * areaServers;

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

	// Initialize Game Data Fields
	memset(this->diskID, 0, sizeof(this->diskID));
	memset(this->saveID, 0, sizeof(this->saveID));

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
	if (send(this->socket, (char*)response, responseLen, 0) == (int)responseLen)
	{
		// Send Success
		return true;
	}

	// Send Failure
	return false;
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
	if (send(socket, (char*)response, responseLen, 0) == (int)responseLen)
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
			this->asLocalAddr = *(uint32_t *)arg;
			this->asPort = *(uint16_t *)(arg + sizeof(uint32_t));
			printf("EXTIP: %08X, INTIP: %08X, PORT: %04X\n",asExtAddr,asLocalAddr,asPort);
			
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


			//lets cast some fields to get at our data...
			uint8_t * asDiskID = arg;
			uint8_t * serverName = &asDiskID[65]; //For shame...
			uint32_t serverNameLen = strlen((char*)serverName);
			uint16_t * serverLevel = (uint16_t *)&serverName[serverNameLen + 1];
			uint16_t * sType = &serverLevel[1];
			uint16_t * sUnk = &sType[1];
			uint8_t * sStatus = (uint8_t*)&sUnk[1];
			uint8_t * serverID = &sStatus[1];

			// Create Area Server Object
			this->aServ = new AreaServer(this->socket,this->asExtAddr,this->asLocalAddr,this->asPort,(char*)serverName,serverID,ntohs(*serverLevel),*sStatus,ntohs(*sType));

			//REGISTER AREA SERVER...
			areaServers->push_back(this->aServ);

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
			//uint8_t uRes[] = {0x00,0x01};
			printf("RECEIVED AREA SERVER PUBLISH4\n");

			break;
		}
		
		case OPCODE_DATA_AS_UPDATE_USERNUM:
		{
			printf("\033[32mRECEIVED AS_UPDATE_USERNUM!\033[0m\n");
			this->aServ->setUsers(ntohs(*(uint16_t*)(arg + sizeof(uint16_t))));

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
			uint16_t * unk1 = (uint16_t*)arg;
			uint8_t * asDiskID = (uint8_t*)&unk1[1];
			uint8_t * serverName = &asDiskID[65]; //For shame...
			uint32_t serverNameLen = strlen((char*)serverName);
			uint16_t * serverLevel = (uint16_t *)&serverName[serverNameLen + 1];
			uint16_t * sType = &serverLevel[1];
			uint8_t * sStatus = (uint8_t*)&sType[1];
			//uint8_t * serverID = &sStatus[1];
			printf("Set STATUS: %02X\n",*sStatus);			
			this->aServ->setStatus(*sStatus);
			this->aServ->setType(ntohs(*sType));
			this->aServ->setLevel(ntohs(*serverLevel));
			break;
		}						

		case OPCODE_DATA_DISKID:
		{
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
			uint8_t uRes[512] = {0};
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
			printf("RECEIVED DATA_REGISTER_CHAR!\n");
			uint8_t uRes[] = {0x00,0x00};
			printf("Sending REGISTER_CHAROK\n");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_REGISTER_CHAROK);		
			break;				
		}
		
		
		case OPCODE_DATA_UNREGISTER_CHAR:
		{
			printf("RECEIVED DATA_UNREGISTER_CHAR\n");
			uint8_t uRes[] = {0x00,0x00};
			printf("Sending UNREGISTER_CHAROK\n");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_UNREGISTER_CHAROK);
			break;
		}
		
		case OPCODE_DATA_SELECT_CHAR:
		{
			printf("RECEIEVED DATA_SELECT_CHAR\n");
			uint8_t uRes[] = {0x00,0x00};
			printf("Sending SELECT_CHAROK\n");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_SELECT_CHAROK);
			break;
		}
		
		
		case OPCODE_DATA_SELECT2_CHAR:
		{
			printf("RECEIEVED DATA_SELECT2_CHAR\n");
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
			uint16_t lID = ntohs(*(uint16_t*)(arg));			
			printf("RECEIVED DATA_LOBBY_GETSERVERS_GETLIST\n");
			
			if(lID == 0x01)
			{	
				uint8_t rServerNum[2];
				uint16_t * numServers = (uint16_t*)rServerNum;
				*numServers = htons(areaServers->size());
				
				sendPacket30(rServerNum,sizeof(rServerNum),OPCODE_DATA_LOBBY_GETSERVERS_SERVERLIST);					
				uint8_t uRes[AS_LIST_LINE_MAXSIZE] = {0};
				//iterate through all area servers to get their listings...
				for(std::list<AreaServer *>::iterator it = areaServers->begin(); it != areaServers->end();/*takes care of itself...*/)
				{
					AreaServer * as = *it;
					as->GetServerLine(uRes,sizeof(uRes),this->asExtAddr);
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
			
				break;
			}
			
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
			uint16_t gID = ntohs(*(uint16_t*)(arg));
			
			//get guild shop item list...	
			printf("Get Guild Shop Items. GID: %u\n",gID);
			uint8_t uRes[] = {0x00,0x01};
			sendPacket30(uRes,sizeof(uRes),0x7730);
		
		
			uint8_t uRes2[] = {0x00,0x00, 0x00,0x00, 0x00,0xff, 0x00,0x00,0x00,0x01};
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
 * Process accumulated Packets on the RX Buffer
 * @return Processing Result
 */
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
						send(socket, response, sizeof(response), 0);

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

	// Keep Connection alive
	return true;
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
