#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>

#define DEFAULT_PORT    (1234)
#define MAX_LINE        (1000)
#define LISTENQ         (1024)

int Readline(int fd, void *vptr, int maxlen);
int Writeline(int fc, const void *vptr, int maxlen);

int main(int argc, char *argv[]) {
  
  int welcomeSocket;
  int clientSocket;
  char *client_input;
  short unsigned int port;
  char buffer[MAX_LINE];
  struct sockaddr_in servaddr;
  char *endptr;

  /* set port from supplied argument otherwise use default */
  if (argc == 2) {
    port = strtol(argv[1], &endptr, 0);
    if (*endptr) {
      printf("ERROR: invalid port number.\n");
      exit(EXIT_FAILURE);
    }
  } else if (argc < 2 ){
    port = DEFAULT_PORT;
  } else {
    printf("ERROR: invalid arguments.\n");
    exit(EXIT_FAILURE);
  }
  

  if( (welcomeSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    printf("ERROR: can't create welcome socket.\n");
    exit(EXIT_FAILURE);
  }

  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  servaddr.sin_port = htons(port);

  if( bind(welcomeSocket, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0){
    printf("ERROR: can't call bind().\n");
    exit(EXIT_FAILURE);
  }

  if( listen(welcomeSocket, LISTENQ) < 0) {
    printf("ERROR: can't call listen().\n");
    exit(EXIT_FAILURE);
  }

  while(1) {
    memset(&buffer, 0, sizeof(buffer));
    if ( (clientSocket = accept(welcomeSocket, NULL, NULL)) < 0) {
      printf("ERROR: can't call accept().\n");
      exit(EXIT_FAILURE);
    }

    int rl;
    while((rl = Readline(clientSocket, buffer, MAX_LINE-1)) > 0){
      printf("Received: (%d chars) %s",rl-1,buffer);
      if(strstr(buffer,"wget") != NULL){
        printf("This is the url to get: %.*s", sizeof(buffer)-5, buffer + 5);
      }
      Writeline(clientSocket, buffer, strlen(buffer));
      memset(&buffer, 0, sizeof(buffer));
    }
  }
  
  if( close(clientSocket) < 0) {
    printf("ERROR: can't close socket");
    exit(EXIT_FAILURE);
  }

  return 0;

}

int Readline(int sockd, void *vptr, int maxlen) {
    int n, rc;
    char    c, *buffer;

    buffer = vptr;

    for ( n = 1; n < maxlen; n++ ) {
        
        if ( (rc = read(sockd, &c, 1)) == 1 ) {
            *buffer++ = c;
            if ( c == '\n' )
                break;
        }
        else if ( rc == 0 ) {
            if ( n == 1 )
                return 0;
            else
                break;
        }
        else {
            if ( errno == EINTR )
                continue;
            return -1;
        }
    }

    *buffer = 0;
    return n;
}

int Writeline(int sockd, const void *vptr, int n) {
    int      nleft;
    int     nwritten;
    const char *buffer;

    buffer = vptr;
    nleft  = n;

    while ( nleft > 0 ) {
        if ( (nwritten = write(sockd, buffer, nleft)) <= 0 ) {
            if ( errno == EINTR )
                nwritten = 0;
            else
                return -1;
        }
        nleft  -= nwritten;
        buffer += nwritten;
    }

    return n;
}

// references: http://www.paulgriffiths.net/program/c/srcs/echoservsrc.html
