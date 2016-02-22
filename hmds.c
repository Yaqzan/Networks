/*
 ============================================================================
 Name        : hmds.c
 Author      : Yaqzan Ali (yali6@uwo.ca)
 Copyright   : For Assignment 2 of CS3357- Computer Networks
 Description : The Hooli Server. Waits for a connection, authenticates
 	 	 	 	 users, stores and checks checksums, and sends a list back
 	 	 	 	 for files needed
 ============================================================================
 */
#include <zlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <err.h>
#include <hdb.h>
#include <hfs.h>
#include <hiredis/hiredis.h>

#define BACKLOG 25
#define SOCK_TYPE(s) (s == SOCK_STREAM ? "Stream" : s == SOCK_DGRAM ? "Datagram" : \
 s == SOCK_RAW ? "Raw" : "Other")

struct addrinfo* get_server_sockaddr(const char* port){
 struct addrinfo hints;
 struct addrinfo* list;
 memset(&hints, 0, sizeof(struct addrinfo));
 hints.ai_family = AF_INET; // Return socket addresses for our local IPv4 addresses
 hints.ai_socktype = SOCK_STREAM; // Return TCP socket addresses
 hints.ai_flags = AI_PASSIVE; // Socket addresses should be for listening sockets
 int retval = getaddrinfo(NULL, port, &hints, &list);
 if (retval)
	 errx(EXIT_FAILURE, "%s", gai_strerror(retval));
 return list;
}

hdb_connection* con;
char* USERNAME;
/*
 ============================================================================
 Name        : setup
 Author      : Yaqzan Ali
 Copyright   : For Assignment 2 for CS3357- Computer Networks
 Description : Connect to specified redis server
 Arguments   : char* host : The redis host to connect to
 ============================================================================
 */
void setup(char* host)
{
  con = hdb_connect(host);

  // Execute these directly against the Redis server to prevent
  // crashed tests from leaving state on the server that might
  // cause other tests to fail.
  redisReply* reply = redisCommand((redisContext*)con,"FLUSHALL");
  freeReplyObject(reply);
}
/*
 ============================================================================
 Name        : reply_204
 Author      : Yaqzan Ali
 Copyright   : For Assignment 2 for CS3357- Computer Networks
 Description : Send a 204 No files requested message
 Arguments   : int socknfd: Connection code
 ============================================================================
 */
void reply_204(int sockfd){
	syslog(LOG_DEBUG, "204 No Files Requested\n");
	char msg[18];
	 strcpy(msg, "204 No Files Requested\n\n");
	 // Send the message
	 if (send(sockfd, msg, strlen(msg), 0) == -1)
		 err(EXIT_FAILURE, "%s", "Unable to send");
	 return;
}
/*
 ============================================================================
 Name        : reply_401
 Author      : Yaqzan Ali
 Copyright   : For Assignment 2 for CS3357- Computer Networks
 Description : Send a 200 Authorization Error reply
 Arguments   : int socknfd: Connection code
 ============================================================================
 */
void reply_401(int sockfd){
	syslog(LOG_DEBUG, "401 Authentication Error\n");
	char msg[18];
	 strcpy(msg, "401 Unauthorized\n\n");
	 // Send the message
	 if (send(sockfd, msg, strlen(msg), 0) == -1)
		 err(EXIT_FAILURE, "%s", "Unable to send");
	 return;
}
/*
 ============================================================================
 Name        : reply_200
 Author      : Yaqzan Ali
 Copyright   : For Assignment 2 for CS3357- Computer Networks
 Description : Send a 200 Authentication succesfull reply
 Arguments   : char* token : The token to reply with
  			   int socknfd: Connection code
 ============================================================================
 */
void reply_200(int sockfd, char* token){
	syslog(LOG_INFO, "Authentication successful.\n");
	char msg[strlen(token)+ 38];
	 strcpy(msg, "200 Authentication successful\nToken:");
	 strcat(msg, token);
	 strcat(msg, "\n\n");
	 // Send the message
	 if (send(sockfd, msg, strlen(msg), 0) == -1)
		 err(EXIT_FAILURE, "%s", "Unable to send");
	 return;
}
/*
 ============================================================================
 Name        : bind_socket
 Author      : Yaqzan Ali
 Copyright   : For Assignment 2 for CS3357- Computer Networks
 Description : Iterate throgh address list bind to socket
 Arguments   : addrinfo& addr_list : list of ip addresses
 ============================================================================
 */
int bind_socket(struct addrinfo* addr_list){
	struct addrinfo* addr;
	int sockfd;
	// Iterate over the addresses in the list; stop when we successfully bind to one
	for (addr = addr_list; addr != NULL; addr = addr->ai_next){
		// Open a socket
		sockfd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
		// Move on to the next address if we couldn't open a socket
		if (sockfd == -1)
			continue;
		// Try to bind the socket to the address/port
		if (bind(sockfd, addr->ai_addr, addr->ai_addrlen) == -1){
			// If binding fails, close the socket, and move on to the next address
			close(sockfd);
			continue;
		}
		else{
			// Otherwise, we've bound the address to the socket, so stop processing
			break;
		}
	 }
	 // Free the memory allocated to the address list
	 freeaddrinfo(addr_list);
	 // If addr is NULL, we tried every address and weren't able to bind to any

	 if (addr == NULL){
		 err(EXIT_FAILURE, "%s", "Unable to bind");
	 }else{
	 // Otherwise, return the socket descriptor
	 return sockfd;
	 }
}
/*
 ============================================================================
 Name        : wait_for_connection
 Author      : Yaqzan Ali
 Copyright   : For Assignment 2 for CS3357- Computer Networks
 Description : Server waits for a client to connect
 Arguments   : int sockfd: Connection code
 ============================================================================
 */
int wait_for_connection(int sockfd)
{
	syslog(LOG_INFO, "Waiting for connection...\n");
	 struct sockaddr_in client_addr; // Remote IP that is connecting to us
	 unsigned int addr_len = sizeof(struct sockaddr_in); // Length of the remote IP structure
	 char ip_address[INET_ADDRSTRLEN]; // Buffer to store human-friendly IP address
	 int connectionfd; // Socket file descriptor for the new connection

	 // Wait for a new connection
	 connectionfd = accept(sockfd, (struct sockaddr*)&client_addr, &addr_len);

	 // Make sure the connection was established successfully
	 if (connectionfd == -1)
		 err(EXIT_FAILURE, "%s", "Unable to accept connection");

	 // Convert the connecting IP to a human-friendly form and print it
	 inet_ntop(client_addr.sin_family, &client_addr.sin_addr, ip_address, sizeof(ip_address));
	 syslog(LOG_INFO, "Connection accepted from %s\n", ip_address);
	 // Return the socket file descriptor for the new connection
	 return connectionfd;
}
/*
 ============================================================================
 Name        : reply_302
 Author      : Yaqzan Ali
 Copyright   : For Assignment 2 for CS3357- Computer Networks
 Description : Send a 302 Files Requested Message
 Arguments   : int socknfd: Connection code
 ============================================================================
 */
void reply_302(int sockfd, char*files){
	syslog(LOG_DEBUG, "302 Files Requested\n");



	 int bytes = strlen(files);

	 	//Get the length of the integer of the bytes
	 	int length_of_bytes;
	 	if(bytes>=0 && bytes <10)
	 		length_of_bytes = 1;
	 	else if (bytes>=10 && bytes <100)
	 		length_of_bytes = 2;
	 	else if (bytes>=100 && bytes <1000)
	 		length_of_bytes = 3;
	 	else if (bytes>=10000 && bytes <10000)
	 		length_of_bytes = 4;
	 	else if (bytes>=10000 && bytes <100000)
	 		length_of_bytes = 5;
	 	else if (bytes>=100000 && bytes <1000000)
	 		length_of_bytes = 6;
	 	else if (bytes>=1000000 && bytes <10000000)
	 		length_of_bytes = 7;
	 	else if (bytes>=10000000 && bytes <100000000)
	 		length_of_bytes = 8;
	 	else if (bytes>=100000000 && bytes <1000000000)
	 		length_of_bytes = 9;
	 	else{
	 		err(EXIT_FAILURE, "%s", "Too many files");
	 	}

	 	// Generate list
	 	char msg[27 +length_of_bytes + bytes];

	 	char str[15];
	 	sprintf(str, "%d", bytes);
		strcpy(msg, "302 Files Requested\nLength:");
		strcat(msg, str);
		strcat(msg, "\n\n");
		strcat(msg, files);

		// Send the message
		syslog(LOG_INFO, "Uploading File list\n");
		if (send(sockfd, msg, strlen(msg), 0) == -1)
		 err(EXIT_FAILURE, "%s", "Unable to send");

}
/*
 ============================================================================
 Name        : list
 Author      : Yaqzan Ali
 Copyright   : For Assignment 2 for CS3357- Computer Networks
 Description : Handles the recieving of LIST HMDP messages
 Arguments   : char* msg : the message recieved
  			   int conncetionfd: Connection code
 ============================================================================
 */
void list(char* msg, int connectionfd){
	 syslog(LOG_DEBUG, "LIST msg\n");
	 	 // Tokenizes message with newline splitter
		const char s[2] = "\n";
		char *sub;
		/* get the first token */
		sub = strtok(msg, s);
		//Get token
		sub = strtok(NULL, s);
		char *token = strrchr(sub, ':');
		token = token +1;

		//Verify token
		syslog(LOG_DEBUG, "Verifying token...\n");
		if(!hdb_verify_token(con, token)){
			syslog(LOG_NOTICE, "Token failed to verify\n");
			reply_401(connectionfd);
			return;
		}

		syslog(LOG_DEBUG, "Token Verified\n");
		syslog(LOG_INFO, "Receiving File List\n");

		/* walk through other tokens, get list of files */
		sub = strtok(NULL, s);
		sub = strtok(NULL, s);
		//char* checksum;
		char newmsg[409640];
		int send = 0;
		while( sub != NULL )
		{
			//Print list of files
		  syslog(LOG_DEBUG, "*  %s\n", sub);

		  // Get checksum
		  //checksum = strtok(NULL,s);
		 // char * checksumcmp = hdb_file_checksum(con, USERNAME, sub);
		  if(!hdb_file_exists(con, USERNAME, sub) /*|| strcmp(checksum, checksumcmp)==0*/){
			  strcat(newmsg, sub);
			  strcat(newmsg, "\n");
			  send = 1;
		  }
		  sub = strtok(NULL, s);
		}



		//newmsg[strlen(newmsg)] = '\0';

		if(send ==1){
			syslog(LOG_INFO, "Requested Files:\n%s\n", newmsg);
			reply_302(connectionfd, newmsg);
		}else{
			syslog(LOG_INFO, "No Requested Files\n%s\n", newmsg);
			reply_204(connectionfd);
		}


		return;
}
/*
 ============================================================================
 Name        : auth
 Author      : Yaqzan Ali
 Copyright   : For Assignment 2 for CS3357- Computer Networks
 Description : Handles the recieving of AUTH HMDP messages
 Arguments   : char* msg : the message recieved
  			   int conncetionfd: Connection code
 ============================================================================
 */
void auth(char* msg, int connectionfd){
	syslog(LOG_DEBUG, "AUTH msg\n");
	// Tokenizes the messages between newline chars
	   const char s[2] = "\n";
	   char *token;
	   /* get the first token */
	   token = strtok(msg, s);
	  		//Get Username
		token = strtok(NULL, s);
		char *user = strrchr(token, ':');
		user = user +1;
		if(!user || user == token){
			syslog(LOG_NOTICE, "Incorrect message format\n");
			return;
		}
		USERNAME = user;
		//Get Password
		token = strtok(NULL, s);
		char *pass = strrchr(token, ':');
		pass = pass +1;
		if(!pass || pass == token){
			syslog(LOG_NOTICE, "Incorrect message format\n");
			return;
		}
		//Print username
		syslog(LOG_INFO, "Username: %s\n", user);

		// Authenticate on redis server
		char *ret =  hdb_authenticate(con, user, pass);
		if(ret==NULL){	// If failed to authenticate
			reply_401(connectionfd);
			return;
		}
		//Successfull Authentication
		reply_200(connectionfd, ret);

		return;
}

void handle_connection(int connectionfd)
{
	 char buffer[4096];
	 int bytes_read;
	 do {
		 // Read up to 4095 bytes from the client
		 bytes_read = recv(connectionfd, buffer, sizeof(buffer)-1, 0);
		 // If the data was read successfully
		 if (bytes_read > 0){
			 syslog(LOG_DEBUG, "Message Recieved. Reading...\n");
			 if (strncmp("AUTH", buffer, 4) == 0){

				auth(buffer, connectionfd);
			 } else if(strncmp("LIST", buffer, 4) == 0){
				 if(USERNAME == NULL){
					 reply_401(connectionfd);
					 syslog(LOG_ERR, "USER not authorized\n");
				 }
				 syslog(LOG_DEBUG, "endtering list\n");
				 list(buffer, connectionfd);
			 }else{
				 syslog(LOG_ERR, "ERROR: Message not formatted correctly\n");
				 reply_401(connectionfd);
			 }
		 }
	 } while (bytes_read > 0);

	 // Close the connection
	 close(connectionfd);
}

/*
 ============================================================================
 Name        : main
 Author      : Yaqzan Ali
 Copyright   : For Assignment 2 for CS3357- Computer Networks
 Description : The main function for the Hooli Server
 	 	 	 	 of files
 Arguments   : --port / -p : the port address
 	 	 	   --redis / -r: the redis port
 	 	 	   --verbose / -v : Set the verbose flag to true

 ============================================================================
 */
int main(int argc, char *argv[]) {
	// Open logging
		openlog("hmds",LOG_PERROR | LOG_PID | LOG_NDELAY, LOG_USER);

		int c, option;
		// The default verbose flag
		setlogmask(LOG_UPTO(LOG_DEBUG));
		char* hostname = "localhost";
		char* port = "9000";
		//create the structure for more info on the long options
		static struct option long_options[]={
				{"redis", required_argument, 0, 'r'},
				{"port", required_argument, 0, 'p'},
				{"verbose", no_argument, 0, 'v'},
				{0,0,0,0}
		};
		// parse optional command line arguments with getopt_long
		while ((c=getopt_long(argc, argv, "vr:p:", long_options,&option))!= -1){
			switch(c){
				case 'v':
					setlogmask(LOG_UPTO(LOG_INFO));		// Turn on verbose mode
					break;
				case 'r':
					hostname = optarg;					// Change hostname
					break;
				case 'p':
					port = optarg;						// Change port
					break;
				case '?':
					exit(EXIT_FAILURE);
					break;
			}

		}
		// Setup connection with redis
		setup(hostname);
		// Listen to the port
		struct addrinfo* list = get_server_sockaddr(port);
		// Create a listening socket
		int sockfd = bind_socket(list);
		syslog(LOG_DEBUG, "Program listening on port %s\n", port);

		// Start listening on the socket
		if (listen(sockfd, BACKLOG) == -1)
			err(EXIT_FAILURE, "%s", "Unable to listen on socket");

		// Wait for a connection
		int connectionfd = wait_for_connection(sockfd);
		// Handle a connection
		handle_connection(connectionfd);

		// Close the connection socket

		close(connectionfd);
		close(sockfd);
		syslog(LOG_INFO, "Connection Closed.\n");
		closelog();
		return EXIT_SUCCESS;
}