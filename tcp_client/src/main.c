#include <stdio.h>

#include "tcp_client.h"

static char total_sent = 0;
static char total_received = 0;

/*
Description:
    A callback function that handles a response
Arguments:
    char *: a formatted string to print
Return value:
    Returns a 1 if all responses printed, 0 otherwise
*/
int handle_response(char *handle_input) {
  // take a formatted string, increment to see if done receiving
  total_received++;
  // print response to stdout
  fprintf(stdout, "%s\n", handle_input);
  return (total_received == total_sent);
}

int main(int argc, char *argv[]) {
  Config config;     // client config
  int sockfd;        // socket used to communicate with server
  FILE *client_file; // file to be read

  char *action = {0};
  char *message = {0};
  // fill in a config and look for error
  if (tcp_client_parse_arguments(argc, argv, &config)) {
    return EXIT_FAILURE;
  }

  // determine here if stdin to be used
  if (strcmp(config.file, "-")) {
    // open file with name just parsed
    if ((client_file = tcp_client_open_file(config.file)) == NULL) {
      return EXIT_FAILURE;
    }
  } else {
    // use stdin
    client_file = stdin;
  }

  // connect and get a socket descriptor, check for error
  if ((sockfd = tcp_client_connect(config)) == -1) {
    return EXIT_FAILURE;
  }

  // loop through a file until EOF is reached
  while (tcp_client_get_line(client_file, &action, &message) != -1) {
    // send a request, check for error
    if (strcmp(config.file, "-")) {
      message[strlen(message) - 1] = '\0';
    }
    if (tcp_client_send_request(sockfd, action, message)) {
      return EXIT_FAILURE;
    }
    free(action);
    free(message);
    total_sent++;
  }

  if (total_sent > 0) {
    // receive response, check for error
    if (tcp_client_receive_response(sockfd, handle_response)) {
      return EXIT_FAILURE;
    }
  }

  // close socket
  if (tcp_client_close(sockfd)) {
    return EXIT_FAILURE;
  }

  // close file
  if (tcp_client_close_file(client_file)) {
    return EXIT_FAILURE;
  }

  return EXIT_SUCCESS;
}