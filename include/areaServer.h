#ifndef _AREASERVER_H_
#define _AREASERVER_H_

#include <stdint.h>

#define AS_LIST_LINE_MAXSIZE 45 // It's actually 43, but we'll give a little wiggle room.

class AreaServer
{
	private:

	// Server Display Name
	char serverName[21];

	// Server ID
	uint8_t serverId[8];

	// Server Port (for people hosting multiple server)
	uint16_t serverPort;

	// Local Server IP (LAN)
	uint32_t serverIPLocal;

	// Public Server IP (WAN)
	uint32_t serverIPExt;

	// Server Level
	uint16_t serverLevel;

	// Server User-Count	
	uint16_t serverUsers;

	// Server Status
	uint8_t serverStatus;

	// SErver Type
	uint16_t serverType;
	
	public:

	// Server Socket
	int socket;

	/**
	 * Area Server Dummy Constructor
	 */
	AreaServer();

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
	AreaServer(int socket, uint32_t eIp, uint32_t lIp, uint32_t port, char* name, uint8_t * id, uint16_t level,uint8_t status,uint16_t type);

	/**
	 * Area Server Destructor
	 */
	~AreaServer();

	/**
	 * Server Status Setter
	 * @param status Server Status
	 */
	void setStatus(uint8_t status);

	/**
	 * Server User Count Setter
	 * @param users Server User Count
	 */
	void setUsers(uint16_t users);

	/**
	 * Server Type Setter
	 * @param type Server Type
	 */
	void setType(uint16_t type);

	/**
	 * Server Level Setter
	 * @param level Server Level
	 */
	void setLevel(uint16_t level);

	/**
	 * Returns the Area Server's Display Name
	 * @return Server Name
	 */
	const char * GetServerName();

	/**
	 * Returns the Area Server's current Level
	 * @return Server Level
	 */
	uint16_t GetServerLevel();

	/**
	 * Returns the Area Server's current Status
	 * @return Server Status
	 */
	uint8_t GetServerStatus();

	/**
	 * Returns the Area Server's current Status in a human-readable fashion
	 * @return Server Status
	 */
	const char * GetServerStatusText();

	/**
	 * Returns the Area Server's current number of active players
	 * @return Player Count
	 */
	uint16_t GetPlayerCount();

	/**
	 * Creates Server Display Structure (for lobby)
	 * @param output Output Buffer
	 * @param outputLen Output Buffer Length (in Bytes)
	 * @param clientIP Public Client IP Address
	 * @param cheaterDetected Anti-Cheat Trigger
	 */
	bool GetServerLine(uint8_t * output,uint16_t outputLen, uint32_t clientIP, bool cheaterDetected);

};

#endif
