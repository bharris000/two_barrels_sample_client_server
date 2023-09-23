#include "tcp_client.h"
#include "log.h"

#define USAGE_PATTERN                                                          \
  "Usage: tcp_client [--help] [-v] [-h HOST] [-p PORT] FILE\n"                 \
  "\n"                                                                         \
  "Arguments:\n"                                                               \
  "\tFILE\tA file name containing actions and messages to\n"                   \
  "\t\tsend to the server. If \"-\" is provided, stdin will\n"                 \
  "\t\tbe read.\n"                                                             \
  "\n"                                                                         \
  "Options:\n"                                                                 \
  "\t--help\n"                                                                 \
  "\t-v, --verbose\n"                                                          \
  "\t--host HOSTNAME, -h HOSTNAME\n"                                           \
  "\t--port PORT, -p PORT\n"

/*
Description:
    Prints instructions on usage pattern
*/
void print_usage() { fprintf(stderr, "%s", USAGE_PATTERN); }

/*
Description:
    Parses the commandline arguments and options given to the program.
Arguments:
    int argc: the amount of arguments provided to the program (provided by the
main function) char *argv[]: the array of arguments provided to the program
(provided by the main function) Config *config: An empty Config struct that will
be filled in by this function. Return value: Returns a 1 on failure, 0 on
success
*/
int tcp_client_parse_arguments(int argc, char *argv[], Config *config) {
  log_set_quiet(true);
  // must be at least one arg
  if (argc < 1) {
    print_usage();
    return EXIT_FAILURE;
  }

  // defaults if no host/port given below
  config->host = TCP_CLIENT_DEFAULT_HOST;
  config->port = TCP_CLIENT_DEFAULT_PORT;

  int opt;
  int option_index = 0;
  static struct option long_options[] = {{"help", no_argument, 0, 0},
                                         {"verbose", no_argument, 0, 'v'},
                                         {"host", required_argument, 0, 'h'},
                                         {"port", required_argument, 0, 'p'},
                                         {0, 0, 0, 0}};

  // parse all options and set info accordingly
  while ((opt = getopt_long(argc, argv, "vh:p:", long_options,
                            &option_index)) != -1) {
    switch (opt) {
    case 'v':
      log_set_quiet(false);
      break;
    case 'h':
      config->host = optarg;
      break;
    case 'p':
      config->port = optarg;
      break;
    default:
      print_usage();
      return EXIT_FAILURE;
    }
  }

  log_info("Attempting to parse.");

  // ports only go up to 65535
  if (atoi(config->port) > 65535 || atoi(config->port) < 1) {
    fprintf(stderr, "invalid port number\n");
    return EXIT_FAILURE;
  }

  // now there should be no more options, parse file argument
  // make sure we have a valid argument for file
  if ((argc - optind) != 1) {
    fprintf(stderr, "invalid argument count\n");
    print_usage();
    return EXIT_FAILURE;
  }
  config->file = argv[optind];

  log_trace("Arguments accepted. Config:");
  log_trace("\tPort: %s", config->port);
  log_trace("\tHost: %s", config->host);
  log_trace("\tFilename: %s", config->file);

  return EXIT_SUCCESS;
}

///////////////////////////////////////////////////////////////////////
/////////////////////// SOCKET RELATED FUNCTIONS //////////////////////
///////////////////////////////////////////////////////////////////////

/*
Description:
    Creates a TCP socket and connects it to the specified host and port.
Arguments:
    Config config: A config struct with the necessary information.
Return value:
    Returns the socket file descriptor or -1 if an error occurs.
*/
int tcp_client_connect(Config config) {
  int sockfd;
  int status;
  struct addrinfo hints, *res;

  log_trace("Connecting to %s:%s.", config.host, config.port);
  // set up a hints struct for addrinfo
  memset(&hints, 0, sizeof hints); // make sure the struct is empty
  hints.ai_family = AF_UNSPEC;     // don't care IPv4 or IPv6
  hints.ai_socktype = SOCK_STREAM; // TCP stream sockets

  // create address info
  if ((status = getaddrinfo(config.host, config.port, &hints, &res)) != 0) {
    fprintf(stderr, "getaddrinfo error: %s\n", gai_strerror(status));
    return -1;
  }

  // open a socket
  sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (sockfd == -1) {
    status = sockfd;
    fprintf(stderr, "socket error: %s\n", gai_strerror(status));
    return -1;
  }

  // connect!
  if ((status = connect(sockfd, res->ai_addr, res->ai_addrlen)) == -1) {
    fprintf(stderr, "connect error: %s\n", gai_strerror(status));
    return -1;
  }

  // free the linked list
  freeaddrinfo(res);

  log_info("Connected.");
  return sockfd;
}

/*
Description:
    Creates and sends request to server using the socket and configuration.
Arguments:
    int sockfd: Socket file descriptor
    char *action: The action that will be sent
    char *message: The message that will be sent
Return value:
    Returns a 1 on failure, 0 on success
*/
int tcp_client_send_request(int sockfd, char *action, char *message) {
  // message cannot have length greater than 2^27
  if (strlen(message) > 134217728) {
    fprintf(stderr, "message is too long\n");
    return EXIT_FAILURE;
  }

  uint8_t action_bin = 0;
  if (!(strcmp(action, "uppercase"))) {
    action_bin = 0x01;
  } else if (!(strcmp(action, "lowercase"))) {
    action_bin = 0x02;
  } else if (!(strcmp(action, "reverse"))) {
    action_bin = 0x04;
  } else if (!(strcmp(action, "shuffle"))) {
    action_bin = 0x08;
  } else if (!(strcmp(action, "random"))) {
    action_bin = 0x10;
  }
  uint32_t command = action_bin << 27;
  command += strlen(message);
  log_debug("Action and lengtn in hex: %X.", command);

  // create a request based on input parsed
  char *request =
      (char *)malloc(sizeof(char) * 32 + sizeof(char) * strlen(message) + 1);
  // action is 4 bytes then length of message
  size_t full_length = strlen(message) + sizeof(char) * 4;

  // place action and length into request buffer
  request[0] = (uint8_t)(command >> 24);
  request[1] = (uint8_t)(command >> 16);
  request[2] = (uint8_t)(command >> 8);
  request[3] = (uint8_t)(command);

  // place message into request buffer
  for (uint i = 0; i < strlen(message); ++i) {
    request[i + 4] = message[i];
  }

  log_trace("Sending message in hex");
  int bytes_sent = 0;
  size_t total_sent = 0;
  // send until full request has been sent
  while (true) {
    bytes_sent =
        send(sockfd, request + total_sent, full_length - total_sent, 0);
    // error check
    if (bytes_sent == -1) {
      fprintf(stderr, "send error: %s\n", gai_strerror(bytes_sent));
      free(request);
      return EXIT_FAILURE;
    }

    // check if we have sent full request, otherwise send again
    total_sent += bytes_sent;
    if (total_sent == full_length) { // may need >= if we enter an infinite loop
      free(request);
      return EXIT_SUCCESS;
    }
  }
}

/*
Description:
    Receives the response from the server. The caller must provide a function
pointer that handles the response and returns a true value if all responses have
been handled, otherwise it returns a false value. After the response is handled
by the handle_response function pointer, the response data can be safely
deleted. The string passed to the function pointer must be null terminated.
Arguments:
    int sockfd: Socket file descriptor
    int (*handle_response)(char *): A callback function that handles a response
Return value:
    Returns a 1 on failure, 0 on success
*/
int tcp_client_receive_response(int sockfd, int (*handle_response)(char *)) {
  int bytes_read = 0;          // bytes read on each iteration of recv
  size_t total_bytes_read = 0; // total bytes read
  size_t buf_size = 2;         // current buffer size
  char *buf =
      (char *)malloc(sizeof(char) * buf_size); // buffer to hold responses

  log_info("Attempting to receive.");

  while (true) {
    // first check if we need to realloc
    if (total_bytes_read + 1 >= buf_size) {
      log_warn("Reallocating for reception.");
      buf_size = buf_size * 2;
      buf = (char *)realloc(buf, sizeof(char) * buf_size);
    }

    // receive
    bytes_read = recv(sockfd, buf + total_bytes_read,
                      sizeof(char) * (buf_size - total_bytes_read - 1), 0);
    // error check
    if (bytes_read == -1 || bytes_read == 0) {
      fprintf(stderr, "receive error: %s\n", gai_strerror(bytes_read));
      free(buf);
      return EXIT_FAILURE;
    }
    total_bytes_read += bytes_read;
    log_trace("Received hex message.");

    // loop thorugh if we have 4 bytes of info
    while (total_bytes_read > 4) {
      // put a null after what we have received for using length later
      buf[total_bytes_read] = '\0';

      // length we should be looking for: add up first four bytes
      uint32_t message_length = 0;
      message_length += buf[0] << 24;
      message_length += buf[1] << 16;
      message_length += buf[2] << 8;
      message_length += buf[3];

      // how much space we actually see from what is received so far
      // find first null after the first 4 length bytes
      size_t actual_length = strlen(buf + 4);

      // check if we need to recv more
      if (actual_length < message_length) {
        break;
      }

      log_trace("Received full message.");

      // make a message to send with \0 at end
      char *message_to_handle;
      message_to_handle = buf + 4;
      message_to_handle[message_length] = '\0';

      // handle the response, return if done
      log_debug("Handling: \"%s\".", message_to_handle);
      if (handle_response(message_to_handle)) {
        // done, free buffer
        free(buf);
        return EXIT_SUCCESS;
      } else {
        // move the buffer pointer
        size_t bytes_remaining = total_bytes_read - 4 - message_length;
        memmove(buf, buf + 4 + message_length, bytes_remaining);
        total_bytes_read = bytes_remaining;
      }
    }
  }

  // shouldn't get here
  free(buf);
  return EXIT_FAILURE;
}

/*
Description:
    Closes the given socket.
Arguments:
    int sockfd: Socket file descriptor
Return value:
    Returns a 1 on failure, 0 on success
*/
int tcp_client_close(int sockfd) {
  int status;
  // close socket, send error if necessary
  if ((status = close(sockfd)) == -1) {
    fprintf(stderr, "close error: %s\n", gai_strerror(status));
    return EXIT_FAILURE;
  } else {
    log_info("Client socket closed.");
    return EXIT_SUCCESS;
  }
}

///////////////////////////////////////////////////////////////////////
//////////////////////// FILE RELATED FUNCTIONS ///////////////////////
///////////////////////////////////////////////////////////////////////

/*
Description:
    Opens a file.
Arguments:
    char *file_name: The name of the file to open
Return value:
    Returns NULL on failure, a FILE pointer on success
*/
FILE *tcp_client_open_file(char *file_name) {
  // open a file with read privileges
  FILE *client_file = fopen(file_name, "r");
  if (client_file == NULL) {
    fprintf(stderr, "File: \"%s\" is NULL.\n", file_name);
    return NULL;
  } else {
    log_debug("File opened: \"%s\".", file_name);
    return client_file;
  }
}

/*
Description:
    Gets the next line of a file, filling in action and message. This function
should be similar design to getline() (https://linux.die.net/man/3/getline).
*action and message must be allocated by the function and freed by the caller.*
When this function is called, action must point to the action string and the
message must point to the message string. Arguments: FILE *fd: The file pointer
to read from char **action: A pointer to the action that was read in char
**message: A pointer to the message that was read in Return value: Returns -1 on
failure, the number of characters read on success
*/
int tcp_client_get_line(FILE *fd, char **action, char **message) {
  char *line = NULL;
  int chars_read = 0;
  size_t line_length = 0;

  // getline, checking for EOF
  log_info("Attempting getline.");
  while ((chars_read = getline(&line, &line_length, fd)) != -1) {
    // allocate memnory for action/message to be freed by caller
    *action = (char *)malloc(sizeof(char) * chars_read);
    *message = (char *)malloc(sizeof(char) * chars_read);

    // make sure there are at least two strings to read
    if (sscanf(line, "%s %[^\n]", *action, *message) < 2) {
      // skip incorrectly formatted request
      log_warn("Skipping incorrectly formatted request.");
      free(*action);
      free(*message);
      continue;
    } else if (strcmp(*action, "uppercase") && strcmp(*action, "lowercase") &&
               strcmp(*action, "reverse") && strcmp(*action, "shuffle") &&
               strcmp(*action, "random")) {
      // skip incorrect action
      log_warn("Skipping incorrect action.");
      free(*action);
      free(*message);
      continue;
    }

    log_debug("Action: %s Message: %s", *action, *message);
    break;
  }

  free(line);
  return chars_read;
}

/*
Description:
    Closes a file.
Arguments:
    FILE *fd: The file pointer to close
Return value:
    Returns a 1 on failure, 0 on success
*/
int tcp_client_close_file(FILE *fd) {
  int status;
  if ((status = fclose(fd))) {
    fprintf(stderr, "error closing file: %s\n", gai_strerror(status));
    return EXIT_FAILURE;
  } else {
    log_info("File closed.");
    return EXIT_SUCCESS;
  }
}