#include "areaServer.h"
#include <string.h>
#include <netinet/in.h>
#include <stdio.h>

/**
 * Area Server Dummy Constructor
 */
AreaServer::AreaServer()
{
	// Init everything to 0?
	this->serverIPExt = 0;
	this->serverIPLocal = 0;
	this->serverPort = 0;
	this->serverUsers = 0;
	this->serverType = 0;	
	this->serverLevel = 0;
	this->serverStatus = 0;
}

/**
 * Area Server Constructor
 * @param socket Socket
 * @param eIp External IP (WAN)
 * @param lIp Local IP (LAN)
 * @param port Port
 * @param name Server Name
 * @param id Server ID
 * @param level Server Level
 * @param status Server Status
 * @param type Server Type
 */
AreaServer::AreaServer(int socket, uint32_t eIp, uint32_t lIp, uint32_t port, char* name, uint8_t * id, uint16_t level,uint8_t status,uint16_t sType)
{
	// Save Arguments
	this->socket = socket;
	this->serverIPExt = eIp;
	this->serverIPLocal = lIp;
	this->serverPort = port;
	strncpy((char*)this->serverName,name,20);
	this->serverName[20] = 0x00;
	memcpy(this->serverId,id,8);
	this->serverStatus = 0;
	this->serverUsers = 0;
	this->serverLevel = level;	
	this->serverType = sType;

	// Notify Administrator
	printf("REGISTERING AREA SERVER: %s, ID:%08X, STATUS:%02X, LEVEL:%02X, USERS:%02X, TYPE: %02X\n",this->serverName, (uint32_t)this->serverId,this->serverStatus,this->serverLevel,this->serverUsers, this->serverType);
}

/**
 * Area Server Destructor
 */
AreaServer::~AreaServer()
{
	// Nothing to really do yet...
};

/**
 * Server Status Setter
 * @param status Server Status
 */
void AreaServer::setStatus(uint8_t status)
{
	// Set Server Status
	this->serverStatus = status;
}

/**
 * Server User Count Setter
 * @param users Server User Count
 */
void AreaServer::setUsers(uint16_t users)
{
	// Set Server User Count
	this->serverUsers = users;
}

/**
 * Server Type Setter
 * @param type Server Type
 */
void AreaServer::setType(uint16_t type)
{
	// Set Server Type
	this->serverType = type;
}

/**
 * Server Level Setter
 * @param level Server Level
 */
void AreaServer::setLevel(uint16_t level)
{
	// Set Server Level
	this->serverLevel = level;
}

/**
 * Creates Server Display Structure (for lobby)
 * @param output Output Buffer
 * @param outputLen Output Buffer Length (in Bytes)
 * @param clientIP Public Client IP Address
 */
bool AreaServer::GetServerLine(uint8_t * output,uint16_t outputLen, uint32_t clientIP)
{
	// Invalid Arguments
	if (output == NULL || outputLen <= 0) return false;

	// Minimum Buffer Length
	uint32_t minimumBufferLength = 1 + 4 + 2 + strlen(this->serverName) + 1 + 2 + 2 + 2 + 1 + 8;

	// Buffer Underflow
	if (outputLen < minimumBufferLength) return false;

	// Cast Fields
	uint8_t * unk1 = output;
	uint32_t * sAddr = (uint32_t *)&unk1[1];
	uint16_t * sPort = (uint16_t *)&sAddr[1];
	char * sName = (char *)&sPort[1];
	uint32_t sNLen = strlen(this->serverName) + 1;
	uint16_t * sLevel = (uint16_t *)&sName[sNLen];
	uint16_t * sType = &sLevel[1];
	uint16_t * sUsers = &sType[1];
	uint8_t * sStatus = (uint8_t *)&sUsers[1];
	uint8_t * sID = &sStatus[1];
	
	// Set Unknown Field Value
	*unk1 = 0x00;

	// Server & Client are behind the same Router
	if (clientIP == this->serverIPExt)
	{
		// Use Local IP Address
		*sAddr = this->serverIPLocal;
	}

	// Server & Client belong to different IP Addresses
	else
	{
		// Use Public IP Address
		*sAddr = this->serverIPExt;
	}
	
	// Set Server Port
	*sPort = this->serverPort;

	// Set Server Display Name
	strcpy(sName,this->serverName);

	// Set Server Level
	*sLevel = htons(this->serverLevel);

	// Set Server Type
	*sType = htons(this->serverType);

	// Set Number of active Server Users
	*sUsers = htons(this->serverUsers);

	// Set Server Status
	*sStatus = this->serverStatus;

	// Set Server ID
	memcpy(sID,this->serverId,8);

	// Structure successfully crafted
	return true;
}

