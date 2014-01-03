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

	// Singleton Constructor
	Server();

	// Singleton Destructor
	~Server();

	public:

	// Instance Guardian
	static Server * getInstance();

	// Instance Destroyer
	static void release();

	// Return Client List
	std::list<Client *> * GetClientList();
};

#endif

