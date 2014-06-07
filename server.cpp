#include "server.h"

// Singleton Instance
Server * Server::instance = NULL;

/**
 * Singleton Instance Getter
 * @return Singleton Instance
 */
Server * Server::getInstance()
{
	// First Time Call
	if(Server::instance == NULL)
	{
		// Create Instance
		Server::instance = new Server();
	}

	// Return Instance
	return Server::instance;
}

/**
 * Free Singleton Memory
 */
void Server::release()
{
	// Instance available
	if(Server::instance != NULL)
	{
		// Free Memory
		delete Server::instance;
	}
}

/**
 * Server Constructor
 */
Server::Server()
{
	// Create Client List
	clients = new std::list<Client *>();

	// Create Area Server List
	areaServers = new std::list<AreaServer *>();
}

/**
 * Server Destructor
 */
Server::~Server()
{
	// Iterate Clients
	for(std::list<Client *>::iterator it = clients->begin(); it != clients->end(); /* Handled in Code */)
	{
		// Fetch Client
		Client * client = *it;

		// Remove Client from List
		clients->erase(it++);

		// Free Client Memory
		delete client;
	}

	// Free Client List
	delete clients;

	// Free Area Server List (no need to free items, they were created and destroyed inside the Client objects, this list is merely a public getter for faster querying)
	delete areaServers;
}

/**
 * Get Client List from Server
 * @return Client List
 */
std::list<Client *> * Server::GetClientList()
{
	// Return Client List
	return clients;
}

/**
 * Get Area Server List from Server
 * @return Area Server List
 */
std::list<AreaServer *> * Server::GetAreaServerList()
{
	// Return Area Server List
	return areaServers;
}

