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
#include <sys/stat.h>
#include <unistd.h>
#include <stdint.h>
#include <poll.h>

#define BACKLOG 25
#define TYPE_ONE 1
#define TYPE_TWO 2
#define TYPE_ZERO 0
#define UDP_SOCKETS_H
#define UDP_SERVER_H
#define HFTP_MESSAGE_H
#define UDP_MSS 65535
#define REQ_MSS 1472
#define RES_MSS 4
#define TRUE 1
#define FALSE 0
#define TOKEN_LENGTH 16
#define PERCENT 10
hdb_connection* con;

//**********STRUCTS*******************************************

typedef struct
{
  int length;
  uint8_t type;
  uint8_t sequence;
  uint16_t filename_length;
  uint32_t filesize;
  uint32_t checksum;
  uint8_t token[TOKEN_LENGTH];
  uint8_t filename[REQ_MSS - 28];

} control_message;

typedef struct
{
  int length;
  uint8_t type;
  uint8_t sequence;
  uint16_t data_length;
  uint8_t data[REQ_MSS-4];

} data_message;

typedef struct
{
  int length;
  uint8_t buffer[REQ_MSS];
} req_message;

typedef struct
{
  int length;
  uint8_t type;
  uint8_t sequence;
  uint16_t error;
} ack_message;

typedef struct
{
  int length;
  uint8_t buffer[RES_MSS];
} res_message;


typedef struct
{
  struct sockaddr_in addr;
  socklen_t addr_len;
  char friendly_ip[INET_ADDRSTRLEN];
} host;
//******************************************************************
/*
 ============================================================================
 Name        : reply_401
 Author      : Yaqzan Ali
 Copyright   : For Assignment 2 for CS3357- Computer Networks
 Description : Send a 200 Authorization Error reply
 Arguments   : int socknfd: Connection code
 ============================================================================
 */
void reply_401(int sockfd,host* dest){
	syslog(LOG_DEBUG, "401 Authentication Error\n");
	char msg[18];
	 strcpy(msg, "401 Unauthorized\n\n");

	 // Send the message, exit if error
	 if (sendto(sockfd, msg, strlen(msg), 0,(struct sockaddr*)&dest->addr, dest->addr_len)==-1)
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
void reply_200(int sockfd, char* token,host* dest){
	syslog(LOG_INFO, "Authentication successful.\n");

	 char msg[strlen(token)+ 38];
	 strcpy(msg, "200 Authentication successful\nToken:");
	 strcat(msg, token);
	 strcat(msg, "\n\n");

	 // Send the message, exit if error
	 if (sendto(sockfd, msg, strlen(msg), 0,(struct sockaddr*)&dest->addr, dest->addr_len)==-1)
		 err(EXIT_FAILURE, "%s", "Unable to send");

	 return;
}

//************CONNECTION METHODS***************************************

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
//-------------------------------------------------------------------------------
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
//--------------------------------------------------------------------------------
struct addrinfo* get_udp_sockaddr(const char* node, const char* port, int flags)
{
  struct addrinfo hints;
  struct addrinfo* results;
  int retval;

  memset(&hints, 0, sizeof(struct addrinfo));

  hints.ai_family = AF_INET;      // Return socket addresses for our local IPv4 addresses
  hints.ai_socktype = SOCK_DGRAM; // Return UDP socket addresses
  hints.ai_flags = flags;         // Socket addresses should be listening sockets

  retval = getaddrinfo(node, port, &hints, &results);

  if (retval != 0)
  {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(retval));
    exit(EXIT_FAILURE);
  }

  return results;
}
//---------------------------------------------------------------------------
int bind_socket(struct addrinfo* addr_list)
{
  struct addrinfo* addr;
  int sockfd;

  // Iterate through each addrinfo in the list; stop when we successfully bind
  // to one
  for (addr = addr_list; addr != NULL; addr = addr->ai_next)
  {
    // Open a socket
    sockfd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

    // Try the next address if we couldn't open a socket
    if (sockfd == -1)
      continue;

    // Try to bind the socket to the address/port
    if (bind(sockfd, addr->ai_addr, addr->ai_addrlen) == -1)
    {
      // If binding fails, close the socket, and try the next address
      close(sockfd);
      continue;
    }
    else
    {

      // Otherwise, we've bound the address/port to the socket, so stop
      // processing
      break;
    }
  }

  // Free the memory allocated to the addrinfo list
  freeaddrinfo(addr_list);

  // If addr is NULL, we tried every addrinfo and weren't able to bind to any
  if (addr == NULL)
  {
    perror("Unable to bind");
    exit(EXIT_FAILURE);
  }
  else
  {
	  syslog(LOG_DEBUG, "Connection Established.\n");
    // Otherwise, return the socket descriptor
    return sockfd;
  }

}
//----------------------------------------------------------------------------
int create_server_socket(char* port)
{
	syslog(LOG_INFO, "Program listening on port %s", port);
  struct addrinfo* results = get_udp_sockaddr(NULL, port, AI_PASSIVE);
  int sockfd = bind_socket(results);
  syslog(LOG_INFO, "Connection Established");
  return sockfd;
}

//*********************MESSAGES**************************************************
res_message* create_message()
{
  return (res_message*)malloc(sizeof(res_message));
}

//--------------------------------------------------------
req_message* receive_message(int sockfd, host* source)
{

	// Create a request message
	req_message* msg = (req_message*)malloc(sizeof(req_message));

	// Length of the remote IP structure
	source->addr_len = sizeof(source->addr);

	// Read message, storing its contents in msg->buffer, and
	// the source address in source->addr
	msg->length = recvfrom(sockfd, msg->buffer, sizeof(msg->buffer), 0,(struct sockaddr*)&source->addr,&source->addr_len);

	// If a message was read
	if (msg->length > 0){
		// Convert the source address to a human-readable form,
		// storing it in source->friendly_ip
		inet_ntop(source->addr.sin_family, &source->addr.sin_addr,source->friendly_ip, sizeof(source->friendly_ip));

		// Return the message received
		return msg;
	}
	else{
		// Otherwise, free the allocated memory and return NULL
		free(msg);
		return NULL;
	}
}

//--------------------------------------------------------------
void send_ack_message(int sockfd, host* dest, uint8_t seq, int error){
	// Create the ACK
	ack_message* msg = (ack_message*)create_message();


	// Store the type and sequence
	msg->type = 255;
	msg->sequence = seq;

	// If there's an error, store 1
	if (error==TRUE){
		msg->error = htons(1);
	}else{
		msg->error = htons(0);
	}


	// The message is of size 4.
	msg->length = 4;

	// Return the dynamically-allocated message
	res_message* ack =  (res_message*)msg;

	syslog(LOG_DEBUG, "ACK Message Sent | Sequence %i | Error %i\n", seq, msg->error);

	sendto(sockfd, ack->buffer, ack->length, 0,(struct sockaddr*)&dest->addr, dest->addr_len);

}
void timewait(int sockfd, host* dest, int* seq, int seconds, int error){

		int retval;
	  // We will poll sockfd for the POLLIN event
	  struct pollfd fd = {
	    .fd = sockfd,
	    .events = POLLIN
	  };
	  // Poll the socket
	  while(1){
		  retval = poll(&fd, 1, seconds*1000);
		  syslog(LOG_DEBUG, "Waiting for timeout...");
		  if (retval == 1 && fd.revents == POLLIN){
			  //resend ack
			  send_ack_message(sockfd, dest, *seq, error );
		  }
		  else
		  {
			return;
		  }
	  }
}
void update_sequence(int *seq){
	// Update Sequence
	if(*seq==1)
		*seq=0;
	else
		*seq=1;
}
char* handle_auth(int connectionfd, host* source)
{
	syslog(LOG_DEBUG, "Waiting for AUTH message...");
	const char s[2] = "\n";

	while(1) {

		// Read up to 100 bytes from the client
		char buffer[100];

		// Length of the remote IP structure
		source->addr_len = sizeof(source->addr);

		// Attempt to read data
		int bytes_read = recvfrom(connectionfd, buffer, sizeof(buffer), 0,(struct sockaddr*)&source->addr,&source->addr_len);

		// If data comes in
		if (bytes_read > 0){
			// Convert the source address to a human-readable form, storing it in source->friendly_ip
			inet_ntop(source->addr.sin_family, &source->addr.sin_addr,source->friendly_ip, sizeof(source->friendly_ip));


			// Check if message has an AUTH tag
			if (strncmp("AUTH", buffer, 4) == 0){
				// Remove the auth tag
				char* token = strtok(buffer, s);

				// Check if it has a Username field
				token = strtok(NULL, s);
				if (strncmp("Username:", token, 9) == 0){

					// Extract Username
					char *user = (char*)malloc(sizeof(char)*15);
					strcpy(user, (strrchr(token, ':')+1));

					//Check if message has a password field
					token = strtok(NULL, s);
					if (strncmp("Password:", token, 9) == 0){

						// Extract Password
						char *pass = strrchr(token, ':')+1;

						// Authenticate on Redis server
						char *ret =  hdb_authenticate(con, user, pass);

						if(ret==NULL){	// If failed to authenticate
							reply_401(connectionfd, source);
						}else{
							//Successful Authentication
							reply_200(connectionfd, ret, source);
							return user;
						}
						//free (pass);
					}
					free(user);
				}
				//free (token);
			}
		}
		//free(buffer);
	}
}

char* create_filepath(char* root, char* user){
	char* filepath;
	filepath = (char*)malloc(sizeof(char)* (strlen((const char*)root)+ strlen((const char*)user)+1));
	strcpy(filepath, (const char*)root);
	strcat(filepath, "/");
	strcat(filepath, (const char*)user);
	return filepath;

}

//***********************************************************************************
int main(int argc, char *argv[]) {
		// Open logging
		openlog("hftdp",LOG_PERROR | LOG_PID | LOG_NDELAY, LOG_USER);

		int c, option;						// The default verbose flag
		int seconds = 10; 				 	// The time to wait in the TIME_WAIT state
		setlogmask(LOG_UPTO(LOG_DEBUG));	// Set default log mask
		char* hostname = "localhost";		// The host name, default to "localhost"
		char* port = "9000";				// The default network port
		char* root = "/vagrant";	   		// The directory to store the files
		host client;           				// Client's address
		int seq;							// The message sequence starts at 0.
		int error = FALSE;					// The ACK error message
		int count = 1;						// Counter for number of files;


		double percent;						// The percentage of file transferred
		int increment =0;					// The increment for displaying the precent
		int filesize;					 	// The size of the file being transferred
		int data_transferred;				// The amount of data transferred
		//create the structure for more info on the long options
		static struct option long_options[]={
				{"redis", required_argument, 0, 'r'},
				{"port", required_argument, 0, 'p'},
				{"verbose", no_argument, 0, 'v'},
				{"timewait", required_argument, 0, 't'},
				{"dir", required_argument, 0, 'd'},
				{0,0,0,0}
		};

		// parse optional command line arguments with getopt_long
		while ((c=getopt_long(argc, argv, "vr:p:d:t:", long_options,&option))!= -1){
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
				case 'd':
					root = optarg;						// Change directory
					break;
				case 't':
					seconds = atoi(optarg);				// Change timewait
					break;
				case '?':
					exit(EXIT_FAILURE);
					break;
			}

		}

		// Setup connection with Redis
		setup(hostname);

		// Create a listening socket
		int sockfd = create_server_socket(port);

		// Wait for a username and password AUTH request
		char* user = handle_auth(sockfd, &client);

		// Set the directory for file output
		char *directory = create_filepath(root, user);

		// Make directory if directory does not exist
		char make_dir[PATH_MAX] = "mkdir -p ";
		strcat(make_dir, directory);
		syslog(LOG_INFO, "%s", make_dir);
		system(make_dir);

//*************************************************************************************
		while (1){
			int terminate =FALSE;
			seq = 0;
			while(1){

				FILE *fp;							// The file pointer
				control_message* request;			// Holds the control request message
				data_message* data_request;			// Holds the data request message
				char* filename;						// The file name
				// Wait until a proper control message is received.
				int control = FALSE;

				while(control == FALSE){
					// Retrieve message
					request = (control_message*)receive_message(sockfd, &client);
					// If it is an initiation message, with correct sequence

					if(request->sequence == seq){
						if(request->type == TYPE_ONE){
							// convert from network order to host order
							request->filename_length = ntohs(request->filename_length);
							request->filesize = ntohl(request->filesize);
							request->checksum = ntohl(request->checksum);

							// Allocate space for the filename
							filename = (char*)malloc(sizeof(char)*request->filename_length);
							filename[0] = '\0';
							request->filename[request->filename_length]= '\0';

							// Copy over the filename
							strcpy(filename, (char*)request->filename);
								// if s contains "/"
								if (strstr(filename, "/") != NULL) {
									char *last = strrchr(filename, '/');
									if (last != NULL) {
									    syslog(LOG_INFO, "Last token: '%s'", last+1);
									}
									char folder[256];
									strncpy(folder, filename, (int)request->filename_length - strlen(last));
									folder[(int)request->filename_length - strlen(last)] = 0; //null terminate destination
									char full_path[PATH_MAX];
									strcpy(full_path, directory);
									strcat(full_path, "/");
									strcat(full_path, folder);
									char make_path[PATH_MAX] = "mkdir -p ";
									strcat(make_path, full_path);
									system(make_path);
								}

							// Assign the null end character for printing
							filename[request->filename_length]= '\0';

							// Assign terminating Null character for the token
							request->token[TOKEN_LENGTH] = '\0';

							syslog(LOG_INFO, "Token %s", (const char*)request->token);
							syslog(LOG_DEBUG, "Control Initialization Message Received | Sequence %i", request->sequence);
							//Verify token
							if(!hdb_verify_token(con, (const char*)request->token)){

								syslog(LOG_DEBUG, "Token failed to verify\n");
								error = TRUE;
							}

							send_ack_message(sockfd, &client, request->sequence, error);

							control = TRUE;
							update_sequence(&seq);
						}else if(request->type == TYPE_TWO){
							syslog(LOG_DEBUG, "Control Termination Message Received | Sequence %i", request->sequence);

							send_ack_message(sockfd, &client, seq, error);
							timewait(sockfd, &client, &seq, seconds, error);
							control = TRUE;
							terminate = TRUE;
							free(request);
							syslog(LOG_INFO, "Connection terminated.");
						}
					}
				}
				if(terminate)
					break;

	//*************************************************************************************
				// Create the file path
				char *path = (char*)malloc(sizeof(char)*(request->filename_length+1+ strlen(directory)));
				strcpy(path, create_filepath(directory, filename));

				// Open file
				fp = fopen(path, "w");

				filesize = request->filesize; 	// The size of the file being transferred is updated
				data_transferred = 0;			// The amount of data transferred is set to 0
				increment = 0;
				// Transfer until all data received

				while(data_transferred <filesize){

					// read the next message
					data_request = (data_message*)receive_message(sockfd, &client);

					// If it is a data message, continue writing it to file
					if(data_request->type == 3){
						if (data_request->sequence ==seq){
							// Convert from network order to host order
							data_request->data_length = ntohs(data_request->data_length);

							syslog(LOG_DEBUG, "Data Message Received | Sequence %i, %iB", data_request->sequence, data_request->data_length);
							// Send ACK
							send_ack_message(sockfd, &client, seq, error);
							update_sequence(&seq);

							// Write data to file
							fwrite(data_request->data, sizeof(uint8_t), data_request->data_length, fp);

							// Increment data counter
							data_transferred+= data_request->data_length;

							// Calculate percent
							percent = ((double)data_transferred/(double)filesize) *100;

							// Display the progress if percent reaches a given amount (PERCENT)
							if(percent >= increment*PERCENT){
								syslog(LOG_INFO, "(%i) Receiving %s: %i/%iB (%.2f%%)",count,filename, data_transferred ,filesize, percent);
								increment++;
							}

						}else{
							// Send ACK
							send_ack_message(sockfd, &client, seq, error);
						}
					}
					free(data_request);
				}

				count++;
				filename[0] = '\0';
				//free(filename);
				free(request);
				//free(path);

				// Close the file
				fclose(fp);
			}
		}

		// Close the socket
		close(sockfd);
		free(user);
		free(directory);

		syslog(LOG_INFO, "Connection Closed.\n");

		closelog();
		return EXIT_SUCCESS;
}