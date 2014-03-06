#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdlib.h>
#include "opcode.h"
#include "client.h"
#include <ctime>



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
	this->segServer = 1;
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
		sprintf(logFileName,"%s/%s.txt",cwrd,buffer);
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
			
			
			
			uint8_t uRes[] = {0x00,0x00};
			
			if(this->clientType == CLIENTTYPE_GAME)
			{
				sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_LOGON_RESPONSE);
			
			}
			else
			{
				//Area server thinks it's special.
				sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_LOGON_RESPONSE_AS);
			}
			break;	
		}
			
							
											
		case OPCODE_DATA_LOGON_AS2:
		{
			printf("Recieved DATA_LOGON_AS2\n");
			uint8_t uRes[] = {0xde,0xad};
			printf("sending OK\n");
			//Doesn't actually work...
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_LOGON_AS2_RESPONSE);
							
			break;								
		}				
			
		case 0x02:
		{
			printf("Received DATA_PING\n");
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
			uint8_t uRes[] = {0xde, 0xad};
			printf("Sending SAVEID_OK\n");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_SAVEID_OK);	
		
		
			break;
		}																						
		
		case OPCODE_DATA_COM:
		{
			uint8_t uRes[] = {0xde,0xad};
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
			uint8_t uRes[] = {0x00, 0x01};
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
		
		
		case OPCODE_DATA_NEWS_GETMENU:
		{
			printf("RECEIEVED DATA_NEWS_GETMENU\n");
			uint8_t uRes[] = {0x00,0x00};
			printf("Sending NEWS_GETMENU_OK\n");
			sendPacket30(uRes,sizeof(uRes),OPCODE_DATA_NEWS_GETMENU_OK);
			
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
		
		case OPCODE_DATA_LOGON_REPEAT:
		{
			printf("Recieved DATA_LOGON_REPEAT\n");
			processPacket30(arg, aSize, OPCODE_DATA_LOGON);
								
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
				uint8_t decryptedPacket[0x40C];
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