#include "server.h"

Server * Server::instance = NULL;

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

void Server::release()
{
	// Instance available
	if(Server::instance != NULL)
	{
		// Free Memory
		delete Server::instance;
	}
}

Server::Server()
{
	// Create Client List
	clients = new std::list<Client *>();
}

Server::~Server()
{
	// Iterate Clients
	for(std::list<Client *>::iterator it = clients->begin(); it != clients->end(); ++it)
	{
		// Free Client
		clients->erase(it);
	}

	// Free Client List
	delete clients;
}

std::list<Client *> * Server::GetClientList()
{
	// Return Client List
	return clients;
}

