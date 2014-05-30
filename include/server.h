#ifndef _SERVER_H_
#define _SERVER_H_

#include <list>
#include "client.h"

class Server
{
	private:

	// Server Instance
	static Server * instance;

	// Internal Client List
	std::list<Client *> * clients;

	/**
	 * Server Constructor
	 */
	Server();

	/**
	 * Server Destructor
	 */
	~Server();

	public:

	/**
	 * Singleton Instance Getter
	 * @return Singleton Instance
	 */
	static Server * getInstance();

	/**
	 * Free Singleton Memory
	 */
	static void release();

	/**
	 * Get Client List from Server
	 * @return Client List
	 */
	std::list<Client *> * GetClientList();
};

#endif

