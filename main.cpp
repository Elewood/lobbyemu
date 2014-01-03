#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include "server.h"
#include "error.h"

// Server Status
int _status = 0;

// Function Prototypes
void interrupt(int sig);
void enable_address_reuse(int fd);
void change_blocking_mode(int fd, int nonblocking);
int create_listen_socket(uint16_t port);
int server_loop(int server);

/**
 * Entry Point
 * @param argc Number of Arguments
 * @param argv Arguments
 * @return OS Error Code
 */
int main(int argc, char * argv[])
{
	// Error Code
	int errorCode = ERROR_OK;

	// Register Signal Handler
	signal(SIGINT, interrupt); // CTRL + C
	signal(SIGTERM, interrupt); // kill & killall

	// Create Listening Socket
	int server = create_listen_socket(49000);

	// Created Listening Socket
	if(server != -1)
	{
		// Notify User
		printf("Listening for Connections on TCP Port 49000.\n");

		// Enter Server Loop
		errorCode = server_loop(server);

		// Notify User
		printf("Shutdown complete.\n");
	}

	// Return Error Code
	return errorCode;
}

/**
 * Server Shutdown Request Handler
 * @param sig Captured Signal
 */
void interrupt(int sig)
{
	// Notify User
	printf("Shutting down... please wait.\n");

	// Trigger Shutdown
	_status = 0;
}

/**
 * Enable Address Reuse on Socket
 * @param fd Socket
 */
void enable_address_reuse(int fd)
{
	// Enable Value
	int on = 1;

	// Enable Port Reuse
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
}

/**
 * Change Socket Blocking Mode
 * @param fd Socket
 * @param nonblocking 1 for Nonblocking, 0 for Blocking
 */
void change_blocking_mode(int fd, int nonblocking)
{
	// Change to Non-Blocking Mode
	if(nonblocking) fcntl(fd, F_SETFL, O_NONBLOCK);

	// Change to Blocking Mode
	else
	{
		// Get Flags
		int flags = fcntl(fd, F_GETFL);

		// Remove Non-Blocking Flag
		fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
	}
}

/**
 * Create Port-Bound Listening Socket
 * @param port TCP Port
 * @return Socket Descriptor (or -1 in case of error)
 */
int create_listen_socket(uint16_t port)
{
	// Create Socket
	int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// Created Socket
	if(fd != -1)
	{
		// Enable Address Reuse
		enable_address_reuse(fd);

		// Make Socket Nonblocking
		change_blocking_mode(fd, 1);

		// Prepare Local Address Information
		struct sockaddr_in local;
		memset(&local, 0, sizeof(local));
		local.sin_family = AF_INET;
		local.sin_addr.s_addr = INADDR_ANY;
		local.sin_port = htons(port);

		// Bind Local Address to Socket
		int bindresult = bind(fd, (struct sockaddr *)&local, sizeof(local));

		// Bound Local Address to Socket
		if(bindresult != -1)
		{
			// Switch Socket into Listening Mode
			listen(fd, 10);

			// Return Socket
			return fd;
		}

		// Notify User
		else printf("%s: bind returned %d.\n", __func__, bindresult);

		// Close Socket
		close(fd);
	}

	// Notify User
	else printf("%s: socket returned %d.\n", __func__, fd);

	// Return Error
	return -1;
}

/**
 * Server Main Loop
 * @param server Server Listening Socket
 * @return OS Error Code
 */
int server_loop(int server)
{
	// Set Running Status
	_status = 1;

	// Handling Loop
	while(_status == 1)
	{
		// Accept Loop
		{
			// Accept Result
			int acceptResult = 0;

			// Accept Connections
			do
			{
				// Prepare Address Structure
				struct sockaddr_in addr;
				socklen_t addrlen = sizeof(addr);
				memset(&addr, 0, sizeof(addr));

				// Accept Connection
				acceptResult = accept(server, (struct sockaddr *)&addr, &addrlen);

				// Connection accepted
				if(acceptResult != -1)
				{
					// Switch Socket into Non-Blocking Mode
					change_blocking_mode(acceptResult, 1);

					// Output Information
					printf("Accepted Client into Server!\n");

					// Add Connection to Client List
					Server::getInstance()->GetClientList()->push_back(new Client(acceptResult));
				}
			} while(acceptResult != -1);
		}

		// Fetch Client List
		std::list<Client *> * clients = Server::getInstance()->GetClientList();

		// Iterate Clients
		for(std::list<Client *>::iterator it = clients->begin(); it != clients->end(); /* Handled in Code */)
		{
			// Fetch Client
			Client * client = *it;

			// Receive Data into Networking Buffer
			int recvResult = recv(client->GetSocket(), client->GetRXBuffer(true), client->GetFreeRXBufferSize(), 0);

			// Connection was closed or timed out
			if(recvResult == 0 || (recvResult == -1 && errno != EAGAIN && errno != EWOULDBLOCK) || client->IsTimedOut())
			{
				// Remove User from List
				clients->erase(it++);

				// Free Memory
				delete client;

				// Output Information
				printf("Closed Connection to Client!\n");

				// Continue Iterator
				continue;
			}

			// Received Data
			else if(recvResult > 0)
			{
				// Update RX Buffer Length
				client->MoveRXPointer(recvResult);

				// Output Information
				printf("Received %d Bytes of Data!\n", recvResult);
			}

			// Process RX Buffer
			if(!client->ProcessRXBuffer())
			{
				// Invalid Data was discovered (Hacking Attempt?)
				clients->erase(it++);

				// Free Memory
				delete client;

				// Output Information
				printf("Encountered Invalid Packet Data!\n");

				// Continue Iterator
				continue;
			}

			// Move Iterator
			it++;
		}

		// Prevent CPU Overload (1ms Sleep)
		usleep(1000);
	}

	// Free Buffer Memory
	Server::release();

	// Close Server Socket
	close(server);

	// Return Error Code
	return ERROR_OK;
}

