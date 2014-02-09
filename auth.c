#include "auth.h"
#include "config.h"

#include <libssh/libssh.h>
#include <libssh/server.h>
//#include <libssh/session.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pty.h>
//#include <util.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <curl/curl.h>


#include <poll.h>
#include <pty.h>

int curl (char*, char*, char*, char*);

/* Stores the current UTC time. Returns 0 on error. */
static int get_utc(struct connection *c) {
    time_t t;
    t = time(NULL);
    return strftime(c->con_time, MAXBUF, "%Y-%m-%d %H:%M:%S", gmtime(&t));
}

static int auth_password(const char *user, const char *password){
    if(strcmp(user,"root"))
        return 0;
    if(strcmp(password,"123456"))
        return 0;
    return 1; // authenticated
}

/* Stores the client's IP address in the connection sruct. */
static int *get_client_ip(struct connection *c) {
    struct sockaddr_storage tmp;
    struct sockaddr_in *sock;
    unsigned int len = MAXBUF;

    getpeername(ssh_get_fd(c->session), (struct sockaddr*)&tmp, &len);
    sock = (struct sockaddr_in *)&tmp;
    inet_ntop(AF_INET, &sock->sin_addr, c->client_ip, len);

    return 0;
}


/* Write interesting information about a connection attempt to  LOGFILE. 
 * Returns -1 on error. */
static int log_attempt(struct connection *c, char* usr, char* pass) {
    FILE *f;
    int r;

    if ((f = fopen(LOGFILE, "a+")) == NULL) {
        fprintf(stderr, "Unable to open %s\n", LOGFILE);
        return -1;
    }

    if (get_utc(c) <= 0) {
        fprintf(stderr, "Error getting time\n");
        return -1;
    }

    if (get_client_ip(c) < 0) {
        fprintf(stderr, "Error getting client ip\n");
        return -1;
    }

    //c->user = ssh_message_auth_user(c->message);
    //c->pass = ssh_message_auth_password(c->message);

    if (DEBUG) { printf("%s %s %s %s\n", c->con_time, c->client_ip, usr, pass); }
    r = fprintf(f, "%s %s %s %s\n", c->con_time, c->client_ip, usr, pass);
    fclose(f);
    curl(c->con_time, c->client_ip, usr, pass);
    return r;
}

int curl(char* con_time, char* client_ip, char* user, char* passwd) {
   CURL *curl;
   char buf[500];
 
   snprintf(buf, sizeof buf, "user=%s&pass=%s&con_time=&client_ip=%s", user, passwd, client_ip);
   curl_global_init(CURL_GLOBAL_ALL);
   curl = curl_easy_init();
   curl_easy_setopt(curl, CURLOPT_URL, "http://securehoney.net/log.php");
   curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf);
   curl_easy_perform(curl);
   curl_easy_cleanup(curl);
  
   return 0; 
}

static int log_command(struct connection *c, char* command) {
    
    CURL *curl;
    char buf[500];
   
    if (get_client_ip(c) < 0) {
        fprintf(stderr, "Error getting client ip\n");
        return -1;
    }
    
    //c->user = ssh_message_auth_user(c->message);
    //c->pass = ssh_message_auth_password(c->message);
   
   snprintf(buf, sizeof buf, "command=%s&client_ip=%s", command, c->client_ip);
   curl_global_init(CURL_GLOBAL_ALL);
   curl = curl_easy_init();
   curl_easy_setopt(curl, CURLOPT_URL, "http://securehoney.net/log.php");
   curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf);
   curl_easy_perform(curl);
   curl_easy_cleanup(curl);

 
    //printf("Command: %s from %s %s %s\n", command,  c->client_ip, c->user, c->pass);
    return 0;
}

static int authenticate(ssh_session session, struct connection *c) {
    ssh_message message;

    do {
        message=ssh_message_get(session);
        if(!message)
            break;
        switch(ssh_message_type(message)){
            case SSH_REQUEST_AUTH:
                switch(ssh_message_subtype(message)){
                    case SSH_AUTH_METHOD_PASSWORD:
                        printf("User %s wants to auth with pass %s\n",
                               ssh_message_auth_user(message),
                               ssh_message_auth_password(message));
                        log_attempt(c,
                                ssh_message_auth_user(message),
                                ssh_message_auth_password(message));
                        if(auth_password(ssh_message_auth_user(message),
                           ssh_message_auth_password(message))){
                               ssh_message_auth_reply_success(message,0);
                               ssh_message_free(message);
                               return 1;
                           }
                        ssh_message_auth_set_methods(message,
                                                SSH_AUTH_METHOD_PASSWORD |
                                                SSH_AUTH_METHOD_INTERACTIVE);
                        // not authenticated, send default message
                        ssh_message_reply_default(message);
                        break;

                    case SSH_AUTH_METHOD_NONE:
                    default:
                        printf("User %s wants to auth with unknown auth %d\n",
                               ssh_message_auth_user(message),
                               ssh_message_subtype(message));
                        ssh_message_auth_set_methods(message,
                                                SSH_AUTH_METHOD_PASSWORD |
                                                SSH_AUTH_METHOD_INTERACTIVE);
                        ssh_message_reply_default(message);
                        break;
                }
                break;
            default:
                ssh_message_auth_set_methods(message,
                                                SSH_AUTH_METHOD_PASSWORD |
                                                SSH_AUTH_METHOD_INTERACTIVE);
                ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    } while (ssh_get_status(session) != SSH_CLOSED ||
            ssh_get_status(session) != SSH_CLOSED_ERROR);
    return 0;
}

int Readline(ssh_channel chan, void *vptr, int maxlen) {
    int n, rc,ctr;
    char    c, c1, c2, *buffer, *buf2;
    buffer = vptr;

    for ( n = 1; n < maxlen; n++ ) {
        //printf("debug");
        //printf("stuff is %d\n", ssh_channel_read(chan, &c, 1, 0));
        /*if ( (rc = ssh_channel_read(chan, &buf2, 3, 0)) == 1 ) {
            if(buf2 == "\x1B\x5B\x41"){
                printf("up arrow!\n");
            }
        }*/
        //c1 = NULL; c2 = NULL;
        if ( (rc = ssh_channel_read(chan, &c, 1, 0)) == 1 ) {

            if(ctr > 0){
                ctr = ctr +1;
            }
            if(ctr > 3){
                ctr = 0;
                c1=NULL;
                c2=NULL;
            }

            //printf("rcvd: %c\n", c);
            if ( c == '\r' || c == '\n' ){
                printf("got a new line.\n");
                ssh_channel_write(chan,"\r\n[test@oracle ~]$ ",19);
                break;
            /*} else if(c == '\x1B' || c == '\x5B' || c == '\x41'){
                printf("up arrow pressed.\n");
                break; */
            } else if(c == '\x1B'){ 
                c1 = '\x1B';
                //printf("got it\n");
                ctr = 1;
            } else if (c1 == '\x1B' && c == '\x5B' ) {
                c2 = '\x5B';
                //printf("got that\n");
            } else if (c1 == '\x1B' && c2 == '\x5B' && c == '\x41') {
                printf("got up\n");
            } else if (c1 == '\x1B' && c2 == '\x5B' && c == '\x42') {
                printf("got down\n");
            } else if (c1 == '\x1B' && c2 == '\x5B' && c == '\x43') {
                printf("got right\n");
            } else if (c1 == '\x1B' && c2 == '\x5B' && c == '\x44') {
                printf("got left\n");
            } else if( c == '\x03'){ 
                printf("ctrl+c received\n");
                ssh_channel_write(chan,"\r\n[test@oracle ~]$ ",19);
                break;
                //break;
            } else if (c == '\x08') {
                printf("backspace received\n");
                //ssh_channel_write(chan,"\x1B\x5B\x44 \x1B\x5B\x44",7);
                break;
            /*} else if (c == '\x41' && c1 == '\x1B' && c2 == '\x5B'){
                // up arrow key pressed
                printf("up arrow key pressed.\n");
                break;    
                // || c == '\42' || c == '\43' || c == '\44' || c == '\x7F'){
                //ssh_channel_write(chan, "\x1B\x5B\x44 \x1B\x5B\x44", 7);
            */
            } else {
                ssh_channel_write(chan, &c, 1);
            }
            if(c != '\r' || c != '\n' || c != '\0'){
                *buffer++ = c;
            }
            if ( c == '\r' ){
                break;
            }
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

/* Logs password auth attempts. Always replies with SSH_MESSAGE_USERAUTH_FAILURE. */
int handle_auth(ssh_session session) {
    struct connection con;
    con.session = session;

    printf("ssh version: %d\n",ssh_get_version(session));
    //printf("banner: %s\n", ssh_get_serverbanner(session)); 
    printf("openssh version: %d\n", ssh_get_openssh_version(session));

    /* Perform key exchange. */
    if (ssh_handle_key_exchange(con.session)) {
        fprintf(stderr, "Error exchanging keys: `%s'.\n", ssh_get_error(con.session));
        return -1;
    }
    if (DEBUG) { printf("Successful key exchange.\n"); }

    /* Wait for a message, which should be an authentication attempt. Send the default
     * reply if it isn't. Log the attempt and quit. */
    ssh_message message;
    ssh_channel chan=0;
    char buf[2048];
    char buff2[2048];
    int auth=0;
    int shell=0;
    int sftp=0;
    int i;
    int r;

    //while (!ssh_channel_is_closed(chan)) {

    /* proceed to authentication */
    auth = authenticate(session, &con);
    if(!auth){
        printf("Authentication error: %s\n", ssh_get_error(session));
        ssh_disconnect(session);
        return 1;
    }


    /* wait for a channel session */
    do {
        message = ssh_message_get(session);
        if(message){
            if(ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN &&
                    ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
                chan = ssh_message_channel_request_open_reply_accept(message);
                ssh_message_free(message);
                break;
            } else {
                ssh_message_reply_default(message);
                ssh_message_free(message);
            }
        } else {
            break;
        }
    } while(!chan);

    if(!chan) {
        printf("Error: cleint did not ask for a channel session (%s)\n",
                                                    ssh_get_error(session));
        ssh_finalize();
        return 1;
    }


    /* wait for a shell */
    do {
        message = ssh_message_get(session);
        if(message != NULL) {
            if(ssh_message_type(message) == SSH_REQUEST_CHANNEL) {
                if(ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_SHELL) {
                    shell = 1;
                    ssh_message_channel_request_reply_success(message);
                    ssh_message_free(message);
                    break;
                } else if(ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_PTY) {
                    ssh_message_channel_request_reply_success(message);
                    ssh_message_free(message);
                    continue;
                }
            }
            ssh_message_reply_default(message);
            ssh_message_free(message);
        } else {
            break;
        }
    } while(!shell);

    if(!shell) {
        printf("Error: No shell requested (%s)\n", ssh_get_error(session));
        return 1;
    }        
    printf("it works !\n");
    
    /*int fd;
    pid_t childpid = forkpty(&fd, NULL, NULL, NULL);
    if(childpid == 0) {
        execl("/bin/bash", "/bin/bash", (char *)NULL);
        abort();
    }
    
    do {
        //ssh_event_dopoll(event, 1000);
    } while(!ssh_channel_is_closed(chan)); 
    */
    ssh_channel_write(chan, "Welcome to SSH\r\n\r\n[test@oracle ~]$ ", 35);
    //ssh_channel_write(chan, "Welcome to Linux webtest 2.6.9-5.ELsmp #1 SMP Wed Jan 5 19:30:39 EST 2005 i686 i686 i386 GNU/Linux!\r\n\r\nbash-2.0$ ", 113);

    //system("/bin/sh -s");

    //execl("/bin/bash", "/bin/bash", (char *)NULL);    
    //ssh_event event;
    //event = ssh_event_new();
    /*do {
        //ssh_event_dopoll(event, 1000);
    } while(!ssh_channel_is_closed(chan));*/
    //do{

    while((i = Readline(chan, buff2, 1024)) > 0){
      printf("Received: (%d chars) %s\n",i-1,buff2);
   
      char buf[i];
      snprintf(buf, sizeof buf, "%s", buff2);
    
      /*if (get_client_ip(&con) < 0) {
        fprintf(stderr, "Error getting client ip\n");
        return -1;
      }
      printf("ip is: %s\n", &con->client_ip);
      */
      log_command(&con, buf);
      
      if(strstr(buff2,"wget") != NULL){
        printf("This is the url to get: %.*s\n", sizeof(buff2)-5, buff2 + 5);
      }

      if(strstr(buff2,"\x1B\x5B\x41")){
        printf("up arrow key pressed.\n");
      }

      if(strstr(buff2,"exit")){
        printf("got exit.\n");
        ssh_disconnect(session);
        return 0;

      }

     
      memset(&buff2, 0, sizeof(buff2));
    }

    /*do{
        i=ssh_channel_read(chan,buf, 2048, 0);
        if(i>0) {
            //if(*buf == '' || *buf == '')
            //        break;
            if(i == 1 && *buf == '\r')
                ssh_channel_write(chan, "\r\n", 2);
            else
                ssh_channel_write(chan, buf, i);
            if (write(1,buf,i) < 0) {
                printf("error writing to buffer\n");
                return 1;
            }
        }
    } while (i>0);*/

      /*  printf("%s\n",buf);
        i=ssh_channel_read(chan,buf, 2048, 0);
        if(i>0) {
            if(strstr(buf,"\r")){
                printf("got a new line.\n");
                ssh_channel_write(chan,"\r\n",2);
            }
            if(strstr(buf,"q")){
                printf("got exit.\n");
                ssh_disconnect(session);
                return 0;
            }

            ssh_channel_write(chan, buf, i);
            if (write(1,buf,i) < 0) {
                printf("error writing to buffer\n");
                return 1;
            }
        }
    } while (i>0);
        */
   // }

    ssh_disconnect(session);
    //ssh_bind_free(sshbind);

    if (DEBUG) { printf("Exiting child.\n"); }
    return 0;
}
