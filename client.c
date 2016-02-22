/*
 ============================================================================
 Name        : client.c
 Author      : Yaqzan Ali (yali6@uwo.ca)
 Copyright   : For Assignment 2 of CS3357- Computer Networks
 Description : Recurses through a given directory and stores files and
 	 	 	 	 CRC-32 checksums into List. Connects to Hooli server
 	 	 	 	 and sends list of files.
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
#include <hiredis/hiredis.h>
#include <hdb.h>
#include <hfs.h>
#include <stdint.h>
#include <unistd.h>
#include <poll.h>
#include <math.h>

#define HFTP_MESSAGE
#define UDP_SOCKETS_H
#define UDP_CLIENT_H
#define REQ_MSS 1472
#define RES_MSS 4
#define TRUE 1
#define FALSE 0
#define TIMEOUT 10000
#define TOKEN_LENGTH 16
#define TYPE_ONE 1
#define TYPE_TWO 2
#define PERCENT 10
typedef struct
{
  int length;
  uint8_t type;
  uint8_t sequence;
  uint16_t filename_length;
  uint32_t filesize;
  uint32_t checksum;
  uint8_t token[16];
  uint8_t filename[REQ_MSS - 28];

} control_message;

typedef struct
{
  int length;
  uint8_t type;
  uint8_t sequence;
  uint16_t data_length;
  uint8_t data[REQ_MSS -4];

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





/*
 ============================================================================

 Name        : get_token
 Author      : Yaqzan Ali
 Copyright   : For Assignment 2 for CS3357- Computer Networks
 Description : Extracts the token from 200 Message
 Arguments   : int connectionfd : the connection value
  			   char* buffer: the 200 message
 ============================================================================
 */
char* get_token(int connectionfd, char* buffer){

		syslog(LOG_INFO, "Authentication Successful");
	 	 // Tokenize with newline splitter
		const char s[2] = "\n";
		char *sub;
		// get the first line
		sub = strtok(buffer, s);
		//Get the second line
		sub = strtok(NULL, s);
		// Get the token
		char *token = strrchr(sub, ':');
		token = token +1;
		return token;
}
// ***********MESSAGE FUNCTIONS*************************************************************************************
char* create_auth_message(char* user, char* pass){
	// Generate authentication message
	int size = strlen(user)+strlen(pass)+ 27;
	char *msg = (char*)malloc(sizeof(char)*size);
	strcpy(msg, "AUTH\nUsername:");
	strcat(msg, user);
	strcat(msg, "\nPassword:");
	strcat(msg, pass);
	strcat(msg, "\n\n");
	return msg;
}

char* create_list_message(char* root, char* token, hfs_entry* files){
	syslog(LOG_DEBUG, "Creating list message\n");

	int bytes =0;								// Number of bytes in the file names

	hfs_entry* cur = files;						// The current entry in the linked list

	//Get exact byte size of body
	while (cur != NULL) {
		bytes +=strlen(cur->rel_path);
	// printf("%s: 0x%x\n", cur->abs_path, cur->crc32);
		cur = cur->next;
	}

	//Get the number of digits in the integer of the bytes
	int length_of_bytes = floor(log10(abs(bytes))) + 1;

	// Put the bytes value into a string
	char buffer[length_of_bytes];
	sprintf(buffer, "%d", bytes);

	// Create the list message
	int size = 37 +length_of_bytes + bytes;
	char *msg = (char*)malloc(sizeof(char)*size);

	// Populate the list message
	strcpy(msg, "LIST\nToken:");
	strcat(msg, token);
	strcat(msg, "\nLength:");
	strcat(msg, buffer);
	strcat(msg, "\n");

	// Go through linked list for paths
	cur = files;
	while (cur != NULL) {
		syslog(LOG_DEBUG, "*  %s\n", cur->rel_path);
		strcat(msg, "\n");
		strcat(msg, cur->rel_path);
		cur = cur->next;
	}
	return msg;
}
req_message* create_message(int size)
{
  return (req_message*)malloc(sizeof(req_message)*size);
}
//----------------------------------------------------------------
res_message* receive_message(int sockfd, host* source)
{
	// Create a response message
	res_message* msg = (res_message*)malloc(sizeof(res_message));

	// Length of the remote IP structure
	source->addr_len = sizeof(source->addr);

	// Read message, storing its contents in msg->buffer, and
	// the source address in source->addr
	msg->length = recvfrom(sockfd, msg->buffer, sizeof(msg->buffer), 0,(struct sockaddr*)&source->addr,&source->addr_len);

	// If a message was read
	if (msg->length > 0){
		// Convert the source address to a human-readable form,
		// storing it in source->friendly_ip
		inet_ntop(source->addr.sin_family, &source->addr.sin_addr,
				  source->friendly_ip, sizeof(source->friendly_ip));

		// Return the message received
		return msg;
	}
	else{
		// Otherwise, free the allocated memory and return NULL
		free(msg);
		return NULL;
	}
}
//----------------------------------------------------------------
int send_message(int sockfd, req_message* msg, host* dest)
{
  return sendto(sockfd, msg->buffer, msg->length, 0,(struct sockaddr*)&dest->addr, dest->addr_len);
}
//-------------------------------------------------------------------------------------------------
req_message* create_control_message(uint8_t type, uint8_t seq, char* name, uint32_t filesize, char* token, uint32_t checksum)
{
	// Create a HFTP Control Request Message
	control_message* msg = (control_message*)create_message(strlen(name)+28);
	int i;

	// Store the type, sequence, and file name length
	msg->type = type;
	msg->sequence = seq;
	msg->filename_length = htons(strlen(name));
	msg->filesize = htonl(filesize);
	msg->checksum = htonl(checksum);

	// Store the token
	for(i=0;i<TOKEN_LENGTH;i++){
		msg->token[i] = token[i];
	}
	// Store the filename
	for(i=0;i<strlen(name);i++){
		msg->filename[i] = name[i];
	}
	msg->filename[msg->filename_length] = 0;
	//syslog(LOG_INFO, "%s", (char*)msg->filename);
	// The message is the length of the file name + 28 bytes of headers.
	msg->length = strlen(name) +28;
	if(type == TYPE_ONE){
		syslog(LOG_DEBUG, "Control Initiation Message Sent | Sequence %i", seq);
	}else{
		syslog(LOG_DEBUG, "Control Termination Message Sent | Sequence %i", seq);
	}
	// Return the dynamically-allocated message
	return (req_message*)msg;
}
//-----------------------------------------------------------------------------------------------
req_message* create_data_message(uint8_t seq, uint16_t length, uint8_t* data)
{
	// Create a HFTP Data Request Message
	data_message* msg = (data_message*)create_message(length+4);
	int i;

	// Store the type, sequence, and file name length
	msg->type = 3;
	msg->sequence = seq;
	msg->data_length = htons(length);
	// Store the data
	for(i=0;i<length;i++){
	  msg->data[i] = data[i];
	}
	// The message is the size of the data + 4 bytes of headers.
	msg->length = (length +4);
	// Return the dynamically-allocated message
	syslog(LOG_DEBUG, "Data Message Sent | Sequence %i | Data: %iB", seq, length);
	return (req_message*)msg;
}

void wait_for_ack(int sockfd, host* dest, int*seq, int* next_seq){
	 int correct = FALSE, retval;
	 while(correct==FALSE){
	  // We will poll sockfd for the POLLIN event
		struct pollfd fd = {
				.fd = sockfd,
				.events = POLLIN
		};
		// Poll the socket for 10 seconds
		retval = poll(&fd, 1, TIMEOUT);
		if (retval == 1 && fd.revents == POLLIN){

			ack_message* response = (ack_message*)receive_message(sockfd, dest);
			response->error = ntohs(response->error);
			syslog(LOG_DEBUG, "ACK Message Received | Sequence: %i | Error : %i\n", response->sequence, response->error);

			if(response->error == 1){
				syslog(LOG_ERR, "Authentication failure");
				perror("Authentication Failure");
				exit(EXIT_FAILURE);
			}

			if(response->sequence==*seq && response->type==255){
				if(*seq==1){
					*seq =0;
					*next_seq = 1;
				}else{
					*seq =1;
					*next_seq = 0;
				}
				correct = TRUE;
			}else{
				syslog(LOG_DEBUG, "Incorrect ACK received. Retrying...\n");
			}
		}else{
			syslog(LOG_WARNING, "Timeout Error. Retrying...\n");
			return;
		}
	 }
}

//********UDP SOCKET FUNCTIONS****************************************************************************************
struct addrinfo* get_udp_sockaddr(const char* node, const char* port, int flags){

	syslog(LOG_DEBUG, "Connecting to HFTP server\n");
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
//----------------------------------------------------------------------------
int create_client_socket(char* hostname, char* port, host* server){
  int sockfd;
  struct addrinfo* addr;
  struct addrinfo* results = get_udp_sockaddr(hostname, port, 0);

  // Iterate through each addrinfo in the list;
  // stop when we successfully create a socket
  for (addr = results; addr != NULL; addr = addr->ai_next)
  {
    // Open a socket
    sockfd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

    // Try the next address if we couldn't open a socket
    if (sockfd == -1)
      continue;

    // Copy server address and length to the out parameter 'server'
    memcpy(&server->addr, addr->ai_addr, addr->ai_addrlen);
    memcpy(&server->addr_len, &addr->ai_addrlen, sizeof(addr->ai_addrlen));

    // We've successfully created a socket; stop iterating
    break;
  }

  // Free the memory allocated to the addrinfo list
  freeaddrinfo(results);

  // If we tried every addrinfo and failed to create a socket
  if (addr == NULL)
  {
    perror("Unable to create socket");
    exit(EXIT_FAILURE);
  }
  else
  {
    // Otherwise, return the socket descriptor
    return sockfd;
  }
}

char* auth_udp(int sockfd, char* user, char* pass, host* dest){

	// Generate AUTH message
	char* msg = create_auth_message(user, pass);

	int retval;


	// Loop until successful Authentication
	syslog(LOG_DEBUG, "Authenticating... \n");
	while(1){

		// Send the AUTH message
		if(sendto(sockfd, msg, strlen(msg), 0,(struct sockaddr*)&dest->addr, dest->addr_len)== -1){
			err(EXIT_FAILURE, "%s", "Unable to send");
		}

		// We will poll sockfd for the POLLIN event
		struct pollfd fd = {
			.fd = sockfd,
			.events = POLLIN
		};

		// Poll the socket for 10 seconds
		retval = poll(&fd, 1, TIMEOUT);

		// If a message was received within 10 seconds
		if (retval == 1 && fd.revents == POLLIN){

			char* response = (char*)malloc(sizeof(char)*54);
			// Length of the remote IP structure
			dest->addr_len = sizeof(dest->addr);

			// Read the  reply
			recvfrom(sockfd, response, 54, 0,(struct sockaddr*)&dest->addr,&dest->addr_len);

			// If 401 Message, exit
			// If 200 Message, break and return token
			if(strncmp("401", response, 3) == 0){
				err(EXIT_FAILURE, "%s", "401 Unauthorized");
			}else if(strncmp("200", response, 3) == 0){
				free(msg);
				return get_token(sockfd, response);
			}
		}else{
			syslog(LOG_WARNING, "Timeout Error. Retrying...\n");
		}
	}
}

//*******TCP SOCKET FUNCTIONS***************************************************************************************
/*
 ============================================================================
 Name        : open_connection
 Author      : Yaqzan Ali
 Copyright   : For Assignment 2 for CS3357- Computer Networks
 Description : Iterates through each address info until connection to server
 Arguments   : struct addrinfo : List of addresses
 ============================================================================
 */
int open_connection(struct addrinfo* addr_list)
{
	 struct addrinfo* addr;
	 int sockfd;
	 // Iterate through each addrinfo in the list; stop when we successfully
	 // connect to one
	 for (addr = addr_list; addr != NULL; addr = addr->ai_next){
		 // Open a socket
		 sockfd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);

		 // Try the next address if we couldn't open a socket
		 if (sockfd == -1)
			 continue;

		 // Stop iterating if we're able to connect to the server
		 if (connect(sockfd, addr->ai_addr, addr->ai_addrlen) != -1)
			 break;
	 }

	 // Free the memory allocated to the addrinfo list
	 freeaddrinfo(addr_list);

	 // If addr is NULL, we tried every addrinfo and weren't able to connect to any
	 if (addr == NULL)
		 err(EXIT_FAILURE, "%s", "Unable to connect");
	 else
		 return sockfd;
}

/*
 ============================================================================
 Name        : get_sockaddr
 Author      : Yaqzan Ali
 Copyright   : For Assignment 2 for CS3357- Computer Networks
 Description : Get's the socket address and connects
 Arguments   : char* hostname	: The hostname
  			   char* port 		: The port address
 ============================================================================
 */
struct addrinfo* get_sockaddr(const char* hostname, const char* port, int protocol)
{
	syslog(LOG_DEBUG, "Connecting to server\n");
	 struct addrinfo hints;
	 struct addrinfo* results;
	 memset(&hints, 0, sizeof(struct addrinfo));

	 hints.ai_family = AF_INET; // Return socket addresses for the server's IPv4 addresses
	 hints.ai_socktype = protocol; // Return TCP socket addresses

	 int retval = getaddrinfo(NULL, port, &hints, &results);

	 if (retval)
		 errx(EXIT_FAILURE, "%s", gai_strerror(retval));

	 syslog(LOG_DEBUG, "Successfully connected to %s\n", hostname);
	 return results;
}

/*
 ============================================================================
 Name        : auth
 Author      : Yaqzan Ali
 Copyright   : For Assignment 2 for CS3357- Computer Networks
 Description : Handles the sending of AUTH HMDP messages
 Arguments   : int sockfd : the connection value
  			   char* user : Username
  			   char* pass : Password
 ============================================================================
 */
void authenticate(int sockfd, char* user, char* pass){
	 // Generate authentication message
	 char* msg = create_auth_message(user, pass);

	 syslog(LOG_INFO, "Authenticating... \n");
	 if (send(sockfd, msg, strlen(msg), 0) == -1){
		err(EXIT_FAILURE, "%s", "Unable to send");
	 }
	 free(msg);
}

/*
 ============================================================================
 Name        : list
 Author      : Yaqzan Ali
 Copyright   : For Assignment 2 for CS3357- Computer Networks
 Description : Handles the sending of LIST HMDP messages
 Arguments   : int sockfd : the connection value
  			   char* token: the token used for verification
  			   char* root : the root directory for scanning
 ============================================================================
 */
void send_list_message(int sockfd, char* token, char* root, hfs_entry* files){

	// Create the list message
	char* msg = create_list_message(root, token, files);

	 // Send the message
	 syslog(LOG_INFO, "Uploading File list\n");
	 if (send(sockfd, msg, strlen(msg), 0) == -1)
		 err(EXIT_FAILURE, "%s", "Unable to send");

	 free(msg);
}
/*
 ============================================================================
 Name        : list_302
 Author      : Yaqzan Ali
 Copyright   : For Assignment 2 for CS3357- Computer Networks
 Description : Handles the recieving of 302 HMDP responses
 Arguments   : char* msg : the message recieved
 ============================================================================
 */
void list_302(char* msg){
	 syslog(LOG_DEBUG, "302 Message\n");
	 	 // Tokenizes message with newline splitter
		const char s[2] = "\n";
		char *sub;
		/* get the first token */
		sub = strtok(msg, s);
		//Get byte size
		sub = strtok(NULL, s);
//		char* cbytes = strrchr(sub, ':');
//		cbytes = cbytes +1;
//		int bytes = atoi(cbytes);

		syslog(LOG_INFO, "Files Requested:\n");
		sub = strtok(NULL, s);
		sub = strtok(NULL, s);
		/* walk through other tokens, get list of files */
		while( sub != NULL )
		{
			//Print list of files
		  syslog(LOG_DEBUG, "*  %s\n", sub);
		  sub = strtok(NULL, s);
		}
		return;
}

char* create_filepath(char* root, char* user){
	char* filepath;
	filepath = (char*)malloc(sizeof(char)* (strlen((const char*)root)+ strlen((const char*)user)+2));
	strcpy(filepath, (const char*)root);
	strcat(filepath, "/");
	strcat(filepath, (const char*)user);
	return filepath;

}

//*********************************************************************************************
/*
 ============================================================================
 Name        : main
 Author      : Yaqzan Ali
 Copyright   : For Assignment 2 for CS3357- Computer Networks
 Description : The main function. Connects to the Hooli Drive and sends list
 	 	 	 	 of files
 Arguments   : Arg1 : Username
  			   Arg2 : Password
 ============================================================================
 */
int main(int argc, char *argv[]) {
		// Open logging
		openlog("client",LOG_PERROR | LOG_PID | LOG_NDELAY, LOG_USER);
		setlogmask(LOG_UPTO(LOG_DEBUG));



		int c, option, sockfd;
		char buffer[4096];				// For storing the received message
		char* port = "9000"; 			// The default port address
		char* fport = "10000";			// The default HFTP port
		char* hostname = "localhost";	// The default host name
		char* fhostname = "localhost";	// The default HFTP host name
		char* root = "~/hooli";			// The default root name for scanning
		host hftp_server;   			// HFTP Server address

		// Long options
		static struct option long_options[]={
				{"server", required_argument, 0, 's'},
				{"port", required_argument, 0, 'p'},
				{"dir", required_argument, 0, 'd'},
				{"verbose", no_argument, 0, 'v'},
				{"fserver", required_argument, 0, 'f'},
				{"fport", required_argument, 0, 'o'},
				{0,0,0,0}
		};
		// Check optional command line arguments
		while ((c=getopt_long(argc, argv, "vs:d:p:f:o:", long_options,&option))!= -1){
			switch(c){
				case 'v':
					setlogmask(LOG_UPTO(LOG_INFO));	// Turn on verbose setting
					break;
				case 's':
					hostname = optarg;	// Change the host name
					break;
				case 'p':
					port = optarg;		// Change the port address
					break;
				case 'd':
					root = optarg;		// Change the root directory
					break;
				case 'f':
					fhostname = optarg;		// Change the
					break;
				case 'o':
					fport = optarg;		// Change the HFTP port address
					break;
				case '?':
					exit(EXIT_FAILURE);
					break;
			}

		}

		// Check if user input required username and password
		if(argv[optind]==NULL || argv[optind+1]==NULL){
			fprintf (stderr, "Error: Incorrect number of arguments.\n"); // Give an error
			return EXIT_FAILURE;
		}
		char* user = argv[optind];
		char* pass = argv[optind+1];

		hfs_entry* files = hfs_get_files(root);		// Scan directory for files and put into linked list

//****************************************************************************************
		 // Connect to the server
		 struct addrinfo* results = get_sockaddr(hostname, port, SOCK_STREAM);
		 sockfd = open_connection(results);

		 //Send AUTH request
		 authenticate(sockfd, user, pass);

		 // Read the  reply
		 recv(sockfd, buffer, sizeof(buffer), 0);
		 if(strncmp("200", buffer, 4) == 0){
			 err(EXIT_FAILURE, "%s", "401 Unauthorized");
		 }
		 syslog(LOG_INFO, "Authentication Successful.\n");
		 //Get  Token
		 char* token = get_token(sockfd, buffer);

		 //Send List
		 send_list_message(sockfd, token, root, files);

		 // Read the  reply
		 recv(sockfd, buffer, sizeof(buffer), 0);

		 // Close the connection
		 close(sockfd);
		// syslog(LOG_INFO, "Connection Closed.\n");

		 // Print requested files
		 syslog(LOG_INFO, "%s", buffer);

		 	 // Tokenizes message with newline splitter
			const char s[2] = "\n";
			char *sub;
			/* get the first token */
			sub = strtok(buffer, s);
			//Get byte size
			sub = strtok(NULL, s);
	//		char* cbytes = strrchr(sub, ':');
	//		cbytes = cbytes +1;
	//		int bytes = atoi(cbytes);
			syslog(LOG_INFO, "*  %s\n", sub);
			syslog(LOG_INFO, "Files Requested:");

			//sub = strtok(NULL, s);
			sub = strtok(NULL, s);


			/* walk through other tokens, get list of files */

//***************************************************************************************

		// Create a socket for communication with the HFTP server
		sockfd = create_client_socket(fhostname, fport, &hftp_server);
		int num_files =0;
		int seq = 0; 		// Initialize sequence number to 0
		int cur_seq = 0;	// Initialize current sequence number to 0
		int next_seq = 1;  // Initialize next sequence to 1

		//Send AUTH request
		token =auth_udp(sockfd, user, pass, &hftp_server);

		hfs_entry* cur = files;						// The current entry in the linked list

		//int i;
		//Get exact byte size of body
		while (cur != NULL) {
			num_files++;
			cur = cur->next;
		}
		//sub = strtok(NULL, s);

		//Iterate through files
		while( sub != NULL ){
			cur = files;
			char *filename;	// The file path relative to root
			int checksum;		// The file checksum

			while (cur != NULL) {
				if(strcmp(sub, cur->rel_path)==0){
					filename = cur->rel_path;
					checksum = cur->crc32;
					break;
				}
				cur = cur->next;
			}

			  num_files++;
			  sub = strtok(NULL, s);


			  syslog(LOG_INFO, "SUB : %s\n", sub);

			uint8_t buffer[REQ_MSS -4]; 	// Holds the file data to be sent
			int buffersize;					// The size of the buffer
			int increment =0;				// The increment for displaying the precent
			double percent;					// The percentage of file transferred
			FILE *fp;						// The file pointer

			char *path = create_filepath(root, filename);


			fp = fopen(path, "r");		// Open the file

			// Get the file size by seeking to the end and getting location
			fseek(fp, 0L, SEEK_END);
			int filesize = ftell(fp);

			// Seek back to the beginning of file
			fseek(fp, 0L, SEEK_SET);

			// Send initialization control message
			cur_seq = seq;
			while(seq==cur_seq){

				// Create type 1 control message, and send
				req_message* control = create_control_message(TYPE_ONE, seq, filename, filesize, token, checksum);
				send_message(sockfd, control, &hftp_server);

				// Wait for an ACK, re-send if timeout
				wait_for_ack(sockfd, &hftp_server, &seq, &next_seq);
				free(control);
			}


			int data_left = filesize;		// The amount of data left to be transferred

			// Begin transferring the current file, piece by piece
			while (data_left >0){

				// Check if the amount of data left exceeds the size limit
				if(data_left > (REQ_MSS -4))
					buffersize = REQ_MSS-4;
				else
					buffersize = data_left;

				// Update the amount of data left to be transferred
				data_left-=buffersize;
				cur_seq= seq;

				// Calculate the percent completed
				percent = (((double)(filesize-data_left)/(double)filesize)*100);

				// If the percent reaches a certain amount (PERCENT), then display progress
				if(percent >=PERCENT*increment){
					syslog(LOG_INFO, "(%i) Transferring %s: %i/%iB (%.2f%%)",num_files,filename, filesize-data_left ,filesize, percent);
					increment++;
				}

				// Read data from the file
				fread(buffer, sizeof(uint8_t), buffersize, fp);

				// Poll and send data message until appropriate ACK received
				while(seq == cur_seq){

					req_message* filesend = create_data_message(seq, buffersize, buffer);
					send_message(sockfd, filesend, &hftp_server);
					wait_for_ack(sockfd, &hftp_server, &seq, &next_seq);
					free(filesend);
				}
			}
			cur = cur->next;
			fclose(fp);
		}

		cur_seq = seq;
		// Send termination control message, until appropriate ACK received

		while(seq==cur_seq){
			// Create type 2 control message, and send
			req_message* control = create_control_message(TYPE_TWO, seq, "Blank", 0, token, 0);
			send_message(sockfd, control, &hftp_server);
			wait_for_ack(sockfd, &hftp_server, &seq, &next_seq);
			free(control);
		}


		close(sockfd);
		closelog();
		syslog(LOG_INFO, "Connection Closed.\n");
		return EXIT_SUCCESS;
}
