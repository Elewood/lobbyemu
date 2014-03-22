#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdlib.h>
#include "opcode.h"
#include "client.h"
#include <ctime>
//#include "sqlite3.h"
#include "areaServer.h"
#include <list>

//extern sqlite3 *srvDatabase;
extern std::list<AreaServer *> * areaServers;

Client::Client(int socket)
{
	// Save Socket
	this->socket = socket;

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
	this->hasSentSwitch = false;
	this->hasFirstServSeg = false;
	this->segServer = 0x0e;
	this->segClient = 0;
	this->opBuster = 0;
	this->lastOp = 0; 


	//disable logging by default?
	this->enableLogging = false;
	
	//If we enable logging...
	if(this->enableLogging)
	{
		time_t curTime;
		struct tm * timeinfo;
		char buffer[256];
	

	
		char logFileName[256];
		char cwrd[256];
		getcwd(cwrd,sizeof(cwrd));
	
	
		
		time(&curTime);
		timeinfo = localtime(&curTime);
		strftime(buffer,256,"%d-%m-%y_%I-%M-%S",timeinfo);
		
		sprintf(logFileName,"%s/logs/%s.txt",cwrd,buffer);
		printf("Opening Log for writing: %s\n",logFileName);
		this->logFile.open(logFileName, std::ios::app);
	}

}



Client::Client(int socket, uint32_t extIp)
{
	// Save Socket
	this->socket = socket;
	this->asExtAddr = extIp;

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
	this->hasSentSwitch = false;
	this->hasFirstServSeg = false;
	this->segServer = 0x0e;
	this->segClient = 0;
	this->opBuster = 0;
	this->lastOp = 0; 


	//disable logging by default?
	this->enableLogging = true;
	
	//If we enable logging...
	if(this->enableLogging)
	{
		time_t curTime;
		struct tm * timeinfo;
		char buffer[256];
	

	
		char logFileName[256];
		char cwrd[256];
		getcwd(cwrd,sizeof(cwrd));
	
	
		
		time(&curTime);
		timeinfo = localtime(&curTime);
		strftime(buffer,256,"%d-%m-%y_%I-%M-%S",timeinfo);
		
		sprintf(logFileName,"%s/logs/%s.txt",cwrd,buffer);
		printf("Opening Log for writing: %s\n",logFileName);
		this->logFile.open(logFileName, std::ios::app);
	}

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
	this->logFile.close();

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

uint32_t Client::getServerSegment()
{
		this->segServer += 1;
		return this->segServer - 1;
}



bool Client::sendPacket30(uint8_t * args, uint32_t aSize, uint16_t opcode)
//Coneveniece function, makes sending 0x30 packets a breeze.
//Automatically tacks on segment, calculates checksum, encrypts and sends.
{
	//packetsize = (checksum)       + (segCount)       + (DataSize)       + (subOpCode)      + aSize
	//packetSize = sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t) + aSize
	uint32_t decryptedResponseLen = sizeof(uint16_t) + sizeof(uint32_t) +	sizeof(uint16_t) + sizeof(uint16_t) + aSize;
	uint32_t dataLen = sizeof(uint32_t) + sizeof(uint16_t) + sizeof(uint16_t) + aSize;
	if(decryptedResponseLen % 8 > 0)
	{
		decryptedResponseLen = decryptedResponseLen / 8;
		decryptedResponseLen = (decryptedResponseLen + 1) * 8;
	}
	
	uint32_t responseLen = decryptedResponseLen + (sizeof(uint16_t) * 2);
	uint8_t* response = new uint8_t[responseLen];

	
			
	uint8_t* decryptedResponse = new uint8_t[decryptedResponseLen];
	
	for(int i = 0; i < decryptedResponseLen; i++) decryptedResponse[i] = 0x0;
	
	//cast fields for encrypted response...
	uint16_t * packetLengthField = (uint16_t *)response;
	uint16_t * packetOpcodeField = &packetLengthField[1];
	uint8_t * packetPayloadField = (uint8_t *)&packetOpcodeField[1];
	
	//cast fields for plaintext payload...
	uint16_t * checksumField = (uint16_t *)decryptedResponse;
	uint32_t * segmentField = (uint32_t *)&checksumField[1];
	uint16_t * lengthField = (uint16_t *)&segmentField[1];
	uint16_t * subOpcodeField = &lengthField[1];
	uint8_t * packetField = (uint8_t *)&subOpcodeField[1];
	
	
	//write static data to final packet buffer...
	*packetLengthField = htons(responseLen - sizeof(*packetLengthField));
	*packetOpcodeField = htons(0x30);
	
	//write static data to plaintext payload...
	*segmentField = htonl(this->getServerSegment());
	*lengthField = htons(aSize + sizeof(uint16_t));
	*subOpcodeField = htons(opcode);
	
	memcpy(packetField, args,aSize);
	
	//calculate checksum
	*checksumField = htons(Crypto::Checksum((uint8_t *)&checksumField[1], dataLen));

	printf("Generated Packet with Checksum: \n");
	for(int i = 0; i < decryptedResponseLen; i++)
	{
		printf("0x%02X",decryptedResponse[i]);
		if(i != decryptedResponseLen - 1)
		{
			printf(",");
		}
	}
	printf("\n");

	
	//encrypt response...
	crypto[KEY_SERVER]->Encrypt(decryptedResponse,decryptedResponseLen,packetPayloadField,&decryptedResponseLen);
	

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
	send(this->socket, (char*)response,responseLen,0);
	return true;
}

bool Client::sendPacket(uint8_t * packet, uint32_t packetSize,uint32_t opcode)
//convenience function, to make sending packets easier. Automatically calculates checksum, encrypts, and sends.
{
	uint32_t decryptedResponseLen = packetSize + sizeof(uint16_t);
	if(decryptedResponseLen % 8 > 0)
	{
		//uint32_t tmpPacketSize
		decryptedResponseLen = decryptedResponseLen / 8;
		decryptedResponseLen = (decryptedResponseLen + 1) * 8;
	}
	uint32_t responseLen = decryptedResponseLen + (sizeof(uint16_t) * 2);
	uint8_t* response = new uint8_t[responseLen];
	
	uint8_t* decryptedResponse = new uint8_t[decryptedResponseLen];

	//cast fields for encrypted response
	uint16_t * packetLengthField = (uint16_t *)response;
	uint16_t * packetOpcodeField = &packetLengthField[1];
	uint8_t * packetPayloadField = (uint8_t *)&packetOpcodeField[1];

	//cast fields for plaintext payload...
	uint16_t * checksumField = (uint16_t *)decryptedResponse;
	uint8_t * packetField = (uint8_t *)&checksumField[1];

	//write static data...
	*packetLengthField = htons(responseLen - sizeof(*packetLengthField));
	*packetOpcodeField = htons(opcode);

	//write packet data...
	memcpy(packetField,packet,packetSize);
	*checksumField = htons(Crypto::Checksum(packet,packetSize));

	printf("Generated Packet With Checksum: \n");
	for(int i = 0; i < decryptedResponseLen;i++)
	{
		printf("0x%02X",decryptedResponse[i]);
		if(i != decryptedResponseLen - 1)
		{
			printf(",");
		}
	}
	printf("\n");

	//encrypt response...
	crypto[KEY_SERVER]->Encrypt(decryptedResponse,decryptedResponseLen,packetPayloadField,&decryptedResponseLen);

//	printf("Encrypted Packet:\n");
//	for(int i = 0; i < responseLen;i++)
//	{
//		printf("0x%02X",response[i]);
//		if(i < responseLen - 1)
//		{
//			printf(",");
	//	}
		
//	}
//	printf("\n");

	send(socket,(char*)response,responseLen,0);
	return true;

}


bool Client::sendNewsCategories()
{

	
	uint8_t uRes[] = {0x00,0x00};
	sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_NEWS_GETMENU_FAILED);

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


bool Client::sendNewsPostList(uint16_t category)
{
	
	
	uint8_t uRes[] = {0x00,0x00};
	sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_NEWS_GETMENU_FAILED);

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


bool Client::sendNewsPost(uint16_t postID)
{
		uint8_t uRes[] = {0x00,0x00};
		sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_NEWS_GETMENU_FAILED);
	
}


void Client::processPacket30(uint8_t * arg, uint16_t aSize, uint16_t opcode)
//this is where we process packet 0x30.
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
				opBuster = 0x7015;
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

			//REGISTER AREA SERVER...

			areaServers->push_back(new AreaServer(this->socket,this->asExtAddr,this->asLocalAddr,this->asPort,(char*)serverName,serverID,ntohs(*serverLevel),*sStatus,ntohs(*sType)));			

			if(this->aServ != NULL)
			{
				printf("I SUCK AT CODING!\n");
			}

			//I'm sure there's a better way to get this...
			this->aServ = areaServers->back();

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
			uint8_t uRes[] = {0x00,0x00};
			printf("RECEIVED AREA SERVER PUBLISH3\n");

			break;
		}			
														
		case OPCODE_DATA_AS_PUBLISH_DETAILS4:
		{
			uint8_t uRes[] = {0x00,0x01};
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
			uint8_t uRes[] = {0x00,0x00};
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
			uint8_t * serverID = &sStatus[1];
			printf("Set STATUS: %02X\n",*sStatus);			
			this->aServ->setStatus(*sStatus);
			this->aServ->setType(ntohs(*sType));
			this->aServ->setLevel(ntohs(*serverLevel));
			break;
		}						
											
		case OPCODE_DATA_DISKID:
		{
			uint8_t uRes[] = {0xff,0xfe,0x00, 0x00};
			printf("Sending DISKID_OK\n");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_DISKID_OK);
			
			break;
		}
			
			
			
			
			
		
			
		case OPCODE_DATA_SAVEID:								
		{
			uint8_t uRes[512] = {0};	
			
			snprintf((char *)uRes,512,MOTD);
			//printf("SENDING: %s\n",uRes);
			printf("Sending SAVEID_OK\n");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_SAVEID_OK);	
		
		
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
		
																			
		case OPCODE_DATA_NEWCHECK:
		{
			printf("Received DATA_NEWCHECK\n");
			uint8_t uRes[] = {0x00, 0x00 };
			printf("Sending NEWCHECK_OK\n");
			//More like "NEW_NONE"
			sendPacket30((uint8_t*)uRes,sizeof(uRes),OPCODE_DATA_NEWCHECK_OK);
			break;
		}
			
		case OPCODE_DATA_MAILCHECK:
		{
			printf("Received DATA_MAILCHECK\n");
			uint8_t uRes[] = {0x00, 0x00};
			printf("sending MAILCHECK_OK\n");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_MAILCHECK_OK);
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
			uint8_t uRes[] = {0x00,0x00};
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
			uint8_t uRes[] = {0x00,0x01,0x0c,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x82,0x61,0x82,0x74,0x82,0x6b,0x82,0x6a,0x82,0x71,0x82,0x6e,0x82,0x72,0x82,0x64};
			sendPacket30(uRes,sizeof(uRes),0x7862);
			
			uint8_t uRes2[] = {0x00,0x01,0x0c,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x82,0x61,0x82,0x74,0x82,0x6b,0x82,0x6a,0x82,0x71,0x82,0x6e,0x82,0x72,0x82,0x64};
			sendPacket30(uRes2,sizeof(uRes2),0x7862);
			uint8_t uRes3[] = {0x00,0x01,0x0c,0x05,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x82,0x61,0x82,0x74,0x82,0x6b,0x82,0x6a,0x82,0x71,0x82,0x6e,0x82,0x72,0x82,0x64};
			sendPacket30(uRes3,sizeof(uRes3),0x7862);
			
			
			
			
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
				uint16_t * thID = (uint16_t *)uRes2;
				uint16_t * thUnk = &thID[1];
				uint8_t * thName = (uint8_t *)&thUnk[1];
				*thID = htons(1);
				snprintf((char*)thName,33,"This is not a real thread...yet.");
				sendPacket30(uRes2,sizeof(uRes2),OPCODE_DATA_BBS_ENTRY_THREAD);
				
			}			
			//7849 threadCat
			//784a error
			//784b catEnrty
			//784c threadList
			//784d threadEnrty			
			
			
			break;
		}
		
		case OPCODE_DATA_BBS_THREAD_GETMENU:
		{
			printf("Getting THREAD!\n");
			uint8_t uRes[] = {0x00,0x01};
			//sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_BBS_THREAD_GETMENU_FAILED);
			//uint8_t uRes[] = {0x00,0x02};
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_BBS_THREAD_LIST);
			
			uint8_t uRes2[742] = {0};
			
			//cast fields...
			uint16_t * pcat = (uint16_t *)uRes2;
			uint16_t * pid = &pcat[1];
			uint8_t * usrName = (uint8_t*)&pid[1];
			uint16_t * unk1 = (uint16_t *)&usrName[76];
			uint16_t * dSize = &unk1[1];
			uint8_t * pTitle = (uint8_t *)&dSize[1];
			uint8_t * pBody = &pTitle[50]; 
			
			
			*pcat = htons(1);
			*pid = htons(1);
			snprintf((char*)usrName,76,"NCDyson");
			*unk1 = htons(0x4019);
			*dSize = htons(0x0280);
			snprintf((char*)pTitle,50,"Test Post");
			snprintf((char*)pBody,590,"Soon");
			
			
			sendPacket30(uRes2,sizeof(uRes2),OPCODE_DATA_BBS_THREAD_GETMENU_FAILED);
			sendPacket30(uRes2,sizeof(uRes2),OPCODE_DATA_BBS_THREAD_ENTRY_POST);
			
			//uint8_t uRes2[] = {0x30,0x30,0x30,0x00,0x31,0x31,0x31,0x31,0x00};
			
			//sendPacket30(uRes2,sizeof(uRes2),OPCODE_DATA_BBS_THREAD_ENTRY_POST);
			//uRes2[0] = 0x31;
			//uRes2[4] = 0x32;
			//sendPacket30(uRes2,sizeof(uRes2),OPCODE_DATA_BBS_THREAD_GETMENU_FAILED);
			//sendPacket30(uRes2,sizeof(uRes2),OPCODE_DATA_BBS_THREAD_);
			
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
			printf("RECEIVED DATA_LOBBY_ENTERROM\n");
			
			uint8_t uRes[] = {0x00,0x01};
			printf("Sending DATA_LOBBY_ENTERROM_OK");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_LOBBY_ENTERROOM_OK);
						
			//uint8_t uRes2[] = {0x00,0x01,0x00,0x0c,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x06,0x57,0x4f,0x4e,0x47,0x46,0x55,0x00};
			uint8_t uRes2[] = {0x00,0x01,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x30,0x00};
			sendPacket30(uRes2,sizeof(uRes2),0x7009);

			sendPacket30(uRes2,sizeof(uRes2),0x700a);
			sendPacket30(uRes2,sizeof(uRes2),0x700b);
			sendPacket30(uRes2,sizeof(uRes2),0x700e);
			
			break;
			
		}
				
						
								
										
														
		case 0x7009:
		{
			//7009 seems to be "LOBBY_FUNC?"
			printf("RECEIVED 0x7009\n");
			printf("sending OK\n");
			uint8_t uRes[] = {0x00,0x00};
			sendPacket30(uRes,sizeof(uRes),0x700a);
			
//			uint8_t uRes2[] = {0x00,0x01,0x30,0x30,0x30,0x31,0x31,0x32,0x32,0x00,0x33,0x33,0x34,0x34,0x00,0x00,0x11,0x82,0x61,0x82,0x74,0x82,0x6b,0x82,0x71,0x82,0x6e,0x82,0x72,0x82,0x64,0x00};
			uint8_t uRes2[] = {0x00,0x01,0x0c,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x82,0x61,0x82,0x74,0x82,0x6b,0x82,0x6a,0x82,0x71,0x82,0x6e,0x82,0x72,0x82,0x64};
			printf("Trying to send some users...\n");
			//send userName...
			//sendPacket30(uRes,sizeof(uRes),0x700a);
//			sendPacket30(uRes2,sizeof(uRes2),0x700b);
	//		sendPacket30(uRes2,sizeof(uRes2),0x7009)

			
						
			uint8_t uRes3[] = {0x00,0x01,0x00,0x0c,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x06,0x57,0x4f,0x4e,0x47,0x46,0x55,0x00};
			sendPacket30(uRes3,sizeof(uRes3),0x7862);
			
			uRes3[4] = 0x05;
			sendPacket30(uRes3,sizeof(uRes3),0x7862);									
															
				
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
			uint8_t uRes[] = {0x00,0x00};
			printf("Sending MAIL_GETOK\n");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_MAIL_GETOK);
					
			break;				
		}		

		
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

						printf("PRE_PACKET\n");
						for(uint32_t i = 0; i < sizeof(decryptedResponse); i++)
						{
							printf("0x%02X",decryptedResponse[i]);
							if( i != sizeof(decryptedResponse) - 1) printf(", ");
							
						}
							
						printf("\n");					
																		
																														
						// Encrypt Response
						uint32_t packetPayloadFieldSize = sizeof(response) - sizeof(*packetLengthField) - sizeof(*packetOpcodeField);
						crypto[KEY_SERVER]->Encrypt(decryptedResponse, sizeof(decryptedResponse), packetPayloadField, &packetPayloadFieldSize);

						for(uint32_t i = 0; i < sizeof(response); i++)
						{
							printf("0x%02X",response[i]);
							if(i != sizeof(response) - 1) printf(",");
						}
												
																								
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

						//Extract ClientSeg-Count
						uint32_t newSeg = ntohl(*(uint32_t *)(decryptedPacket + sizeof(uint16_t)));

						if (newSeg <= this->segClient)
						{
							printf("The Client's Segment was less than or equal to the last one!");
							//return false;
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

						// Output Segment
						printf("Client Segment: 0x%02X\n",newSeg);
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

						if(this->enableLogging)
						{

							char lBuff[16];
							sprintf(lBuff,"%02X",internalOpcode);
							this->logFile << "Recieved 0x30_0x" << lBuff << " ";
							sprintf(lBuff,"0x%02X",decryptedPacketLength);
							this->logFile << lBuff << " bytes of data\n\t";
						
							for(int i = 0;i<decryptedPacketLength;i++)
							{
								sprintf(lBuff,"%02X ",decryptedPacket[i]);
								this->logFile << lBuff;
							}
			
							this->logFile <<	"\n";
						}

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

bool Client::IsTimedOut()
{
	// Calculate Delta Time
	double deltaTime = difftime(time(NULL), this->lastHeartbeat);

	// No Reaction in 30s
	return deltaTime >= 30;
}