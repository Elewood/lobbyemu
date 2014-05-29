#ifndef _AREASERVER_H_
#define _AREASERVER_H_

#include <stdint.h>
//#include <time.h>

#define AS_LIST_LINE_MAXSIZE 45 //It's actually 43, but we'll give a little wiggle room.
class AreaServer
{
	private:
		char serverName[21];
		uint8_t serverId[8];
		uint16_t serverPort;
		uint32_t serverIPLocal;
		uint32_t serverIPExt;
	
		uint16_t serverLevel;	
		uint16_t serverUsers;
		uint8_t serverStatus;
		uint16_t serverType;
		
	public:
		//Constructor
		AreaServer();
		AreaServer(int socket, uint32_t eIp, uint32_t lIp, uint32_t port, char* name, uint8_t * id, uint16_t level,uint8_t status,uint16_t type);
	
		int socket;			
		//Destructor
		~AreaServer();
		
		void setStatus(uint8_t status);
		void setUsers(uint16_t users);
		void setType(uint16_t type);
		void setLevel(uint16_t level);
	
					
		bool GetServerLine(uint8_t * output,uint16_t outputLen, uint32_t clientIP);

};

#endif