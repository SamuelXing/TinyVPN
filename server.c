/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. Handles (badly) IPv4 for tun, ARP and IPv4 for     *
 * tap. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.                     *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2009 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netdb.h>
#include <signal.h>

#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
/* define HOME to be dir for key and cert files.... */
#define HOME "./KEY/"
#define CERTF HOME "server.crt"
#define KEYF HOME "server.key"
#define CACERT HOME "ca.crt"

#define CHK_NULL(x) if((x)==NULL) exit(1)
#define CHK_ERR(err,s) if ((err==-1)) {perror(s);exit(1);}
#define CHK_SSL(err) if(err ==-1) {ERR_print_errors_fp(stderr);exit(2);}

/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

/* some common lengths */
#define IP_HDR_LEN 20
#define ETH_HDR_LEN 14
#define ARP_PKT_LEN 28
#define KEY_IV_LENGTH 16

int debug;
char *progname;

/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            needs to reserve enough space in *dev.                      *
 **************************************************************************/
int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;

  if( (fd = open("/dev/net/tun", O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n))<0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n))<0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts those into "buf".    *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left))==0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  if(debug){
	va_start(argp, msg);
	vfprintf(stderr, msg, argp);
	va_end(argp);
  }
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}

/**************************************************************************
 * handleErrors: Error Handling                                           *
 **************************************************************************/
void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

/**************************************************************************
 * CBCEncrpt:                                        *
 **************************************************************************/
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 128 bit AES (i.e. a 128 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
    handleErrors();

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

/**************************************************************************
 * CBCDecrpt:                                        *
 **************************************************************************/
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;
		
  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) {
	 printf("decrypt new error\n");
	 handleErrors();
  }

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 128 bit AES (i.e. a 128 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
    printf("decrypt init error\n");
    handleErrors();
  }
  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
    printf("decrypt update error\n");
    handleErrors();
  }
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)){
      	 printf("decrypt final error %s,%d\n",plaintext,len);
 	 handleErrors();
  }
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

/**************************************************************************
 * SAH256Hash:                                        *
 **************************************************************************/
int SHA256Hash(const void* mess, int mess_len, const void* key, void* buffer, int* outlen)
{
  //printf("hash len: %d \n", mess_len);
  unsigned char* dgst = 0;
  dgst = HMAC(EVP_sha256(), key, 16, mess, mess_len, buffer, (unsigned int*) outlen);
  if(dgst==0)
  {
    perror("ERROR: not able to generate hash");
    return 0;
  }
  return 1;
}

int HashVerify(const void* data, int datalen, const void* key, const void* hmac)
{
  unsigned int out_len;
  unsigned char out[EVP_MAX_MD_SIZE];
  
  if(HMAC(EVP_sha256(), key, 16, data, datalen, out, &out_len)==0)
  {
    perror("ERROR: not able to generate hash");
    return 0;
  }
  //printf("data: %s\ndatamac: %s, hmac: %s\n",(char*)data, (char*)out,(char*)hmac);
  if(memcmp(out, hmac, out_len)==0) return 1;

  return 0;
}

/**************************************************************************
 * Check Username and Password                                            *
 **************************************************************************/
int validateUser(char* username, char* password)
{
  FILE* fp;
  char* line=NULL;
  size_t len=0;
  int read;
  int flag=0;

  fp=fopen("db.txt","r");
  if(fp==NULL)
    exit(EXIT_FAILURE);

  while((read=getline(&line, &len, fp))!=-1)
  {
    printf("Retrieved line of len %d :\n",read);
    printf("%s", line);
    char* pch1=strtok(line, " ");
    char* pch2=strtok(NULL, " ");
    if(!strcmp(pch1, username) && !strcmp(pch2, password)) flag=1;
  }
  fclose(fp); 

  return flag;
}

int main(int argc, char *argv[]) {
  
  int option;
  int flags = IFF_TUN;
  char if_name[IFNAMSIZ] = "";
  int header_len = IP_HDR_LEN;
  uint16_t nread, nwrite, plength;
//  uint16_t total_len, ethertype;
  char buffer[BUFSIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";
  unsigned short int port = PORT;
  int optval = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  struct sockaddr_in client;
  int clientlen;   
  //////////////////////////////////////
  int err;
  int listen_sd;
  int sd;
  struct sockaddr_in sa_serv;
  struct sockaddr_in sa_cli;
  size_t client_len;
  SSL_CTX* ctx;
  SSL*     ssl;
  X509*    client_cert;
  char*    str;
  char     buf [4096];
  SSL_METHOD *meth;


  /* SSL preliminaries. We keep the certificate and key with the context. */
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();
  meth = SSLv23_server_method();
  ctx = SSL_CTX_new (meth);
  if (!ctx) {
    ERR_print_errors_fp(stderr);
    exit(2);
  }

  SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER,NULL); /* whether verify the certificate */
  SSL_CTX_load_verify_locations(ctx,CACERT,NULL);
  
  if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(3);
  }
  if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
    ERR_print_errors_fp(stderr);
    exit(4);
  }

  if (!SSL_CTX_check_private_key(ctx)) {
    fprintf(stderr,"Private key does not match the certificate public key\n");
    exit(5);
  }
  //////////////////////////////////////

  progname = argv[0];
  
  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0){
    switch(option) {
      case 'd':
        debug = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name,optarg,IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(remote_ip,optarg,15);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        header_len = ETH_HDR_LEN;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0){
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name == '\0'){
    my_err("Must specify interface name!\n");
    usage();
  }else if(cliserv < 0){
    my_err("Must specify client or server mode!\n");
    usage();
  }else if((cliserv == CLIENT)&&(*remote_ip == '\0')){
    my_err("Must specify server address!\n");
    usage();
  }

  
  if(cliserv==SERVER){
    /* Server, wait for connections */
    int pipe_fd[2];
    pipe(pipe_fd);
    fcntl(pipe_fd[0],F_SETFL,O_NONBLOCK);
    pid_t pid=fork();
    /* parent process: TCP channel as control, updating session key, exchanging the IV, termination */ 
    if(pid>0)
    {   
        close(pipe_fd[0]);
        /* ----------------------------------------------- */
        /* Prepare TCP socket for receiving connections */
        listen_sd = socket (AF_INET, SOCK_STREAM, 0);   CHK_ERR(listen_sd, "socket");
        
        memset (&sa_serv, '\0', sizeof(sa_serv));
        sa_serv.sin_family      = AF_INET;
        sa_serv.sin_addr.s_addr = htonl(INADDR_ANY);
        sa_serv.sin_port        = htons (port);          /* Server Port number */
        
        err = bind(listen_sd, (struct sockaddr*) &sa_serv,
             sizeof (sa_serv));                   CHK_ERR(err, "bind");
             
        /* Receive a TCP connection. */
             
        err = listen (listen_sd, 5);                    CHK_ERR(err, "listen");
        
        client_len = sizeof(sa_cli);
        sd = accept (listen_sd, (struct sockaddr*) &sa_cli, &client_len);
        CHK_ERR(sd, "accept");
        close (listen_sd);

        //printf ("Connection from %lx, port %x\n", sa_cli.sin_addr.s_addr, sa_cli.sin_port);
        
        /* ----------------------------------------------- */
        /* TCP connection is ready. Do server side SSL. */

        ssl = SSL_new (ctx);                           CHK_NULL(ssl);
        SSL_set_fd (ssl, sd);
        err = SSL_accept (ssl);                        CHK_SSL(err);
        
        /* Get the cipher - opt */  
        printf ("SSL connection using %s\n", SSL_get_cipher (ssl));


        /* DATA EXCHANGE - Receive message and send reply. */
        unsigned char key[KEY_IV_LENGTH+1]; key[17]='\0';
        unsigned char iv[KEY_IV_LENGTH+1]; iv[17]='\0';

        err = SSL_read (ssl, buf, sizeof(buf) - 1);                   CHK_SSL(err);
        buf[err] = '\0';
        printf ("Got %d chars:'%s'\n", err, buf);
        err = SSL_write (ssl, "I hear you.", strlen("I hear you."));  CHK_SSL(err);   
        // receive key
        err = SSL_read (ssl, key, KEY_IV_LENGTH);                   CHK_SSL(err);
        //key[err] = '\0';
        printf ("Got %d chars:'%s'\n", err, key);
        err = SSL_write (ssl, "I got your key.", strlen("I got your key."));  CHK_SSL(err);
        // receive iv  
         err = SSL_read (ssl, iv, KEY_IV_LENGTH);                   CHK_SSL(err);
        //iv[err] = '\0';
        printf ("Got %d chars:'%s'\n", err, iv);
        err = SSL_write (ssl, "I got your iv", strlen("I got your iv."));  CHK_SSL(err);
        
        /* --------------------------------------------------- */
        /* PASS Key&IV - send key&IV to child Process */
        unsigned char combine[100]="";
				int k;
        combine[0]='k';
        for(k=0;k<KEY_IV_LENGTH;k++)
        {
          combine[k+1]=key[k];
          combine[KEY_IV_LENGTH+k+1]=iv[k];
        }
        int writelen=write(pipe_fd[1], combine, strlen(combine)+1);
        printf("Parent Process: passed Key (%s), IV (%s) \n", key, iv);

        /* --------------------------------------------------- */
        /* Notify the child process to be ready to send packet */
        write(pipe_fd[1],"o", strlen("o")+1); // by default, send 'o' to start UDP communicaiton  

        /* ----------------------------------------------- */
        /* Validate Username & Password  */
        char username[50];
        char password[256];
        err=SSL_read(ssl, username, sizeof(username)-1); CHK_SSL(err);
        username[err]='\0';
        printf("Get username %s\n", username);
        err=SSL_read(ssl, password, sizeof(password)-1); CHK_SSL(err);
        password[err]='\0';
        printf("Get password %s\n", password);
        if(validateUser(username,password))
        {
          printf("User authentication passed!\n");
          err=SSL_write(ssl,"Success", strlen("Success")+1); CHK_SSL(err);
        }
        else
        {
          err=SSL_write(ssl, "Fail", strlen("Fail")+1); CHK_SSL(err);
          printf("Cannot valify user!\n");
          write(pipe_fd[1], "q", strlen("q")+1);
          kill(pid, SIGTERM);
          wait();
        }

        /* Keep Reading TCP command */
        unsigned char command[1024];
        while(1)
        {
          int SSL_err;
          SSL_err=SSL_read(ssl, command, sizeof(command)-1); CHK_SSL(SSL_err);
          command[SSL_err]='\0';
          if(strlen(command)>0)
          {
            if(command[0]=='q' || command[0] == 'Q')
            {
              printf("Client Quit!\n");
              write(pipe_fd[1], command, strlen(command)+1);
              kill(pid, SIGTERM);
              memset(key,0x20, 17); memset(iv, 0x20, 17);
              wait();
              break;
            }
            if(command[SSL_err-1]=='k' || command[SSL_err-1] == 'K')
            {
              printf("Updating Session Key\n");
              //SSL_err=SSL_read(ssl, key, KEY_IV_LENGTH+1); CHK_SSL(SSL_err);
              //key[SSL_err]='\0';
              printf("ReadLen:%d\n",SSL_err);
              strncpy(key,command, SSL_err-2); key[SSL_err-1]='\0';
              printf("New Key: %s\n", key);
              write(pipe_fd[1],command, strlen(command)+1);
              //write(pipe_fd[1], key, strlen(key)+1);
            }
            if(command[0] == 'v' || command[0] == 'V')
            {
              printf("Updating IV\n");
              //SSL_err=SSL_read(ssl, iv, KEY_IV_LENGTH+1); CHK_SSL(SSL_err);
              //iv[SSL_err]='\0';
              printf("ReadLen:%d\n",SSL_err);
              strncpy(iv,command, SSL_err-2); iv[SSL_err-1]='\0';
              printf("New IV:%s\n", iv);
              write(pipe_fd[1],command,strlen(command)+1);
              //write(pipe_fd[1], iv, strlen(iv)+1);
            }
          }
        }

        /* Clean up. */
        close (sd);
        SSL_free (ssl);
        SSL_CTX_free (ctx);
    }
    else
    {
        close(pipe_fd[1]);
        usleep(1000);
        unsigned char combine[100];
        unsigned char command[5];
        unsigned char key[16]; 
        unsigned char iv[16]; 
        int cmdLen=0; int OK=0;
        int maxfd, tap_fd, net_fd, sock_fd;
        unsigned long int tap2net = 0, net2tap = 0;

        /* initialize tun/tap interface */
        if ( (tap_fd = tun_alloc(if_name, flags | IFF_NO_PI)) < 0 ) {
          my_err("Error connecting to tun/tap interface %s!\n", if_name);
          exit(1);
        }

         do_debug("Successfully connected to interface %s\n", if_name);

        /* child process: UDP channel, tunnel channel */
        // setup UDP fd
        if((sock_fd = socket(AF_INET,SOCK_DGRAM, IPPROTO_UDP))<0){
          perror("socket()");
          exit(1);
        }
        /* avoid EADDRINUSE error on bind() */
        if(setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, (char *)&optval, sizeof(optval)) < 0){
          perror("setsockopt()");
          exit(1);
        }
        
        memset(&local, 0, sizeof(local));
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_ANY);
        local.sin_port = htons(port);
        if (bind(sock_fd, (struct sockaddr*) &local, sizeof(local)) < 0){
          perror("bind()");
          exit(1);
        }
        /* wait for connection request */
        // remove TCP connection logic
        remotelen = sizeof(remote);
        memset(&remote, 0, remotelen);
        net_fd=sock_fd;
        //do_debug("SERVER: Client connected from %s\n", inet_ntoa(remote.sin_addr));

        /* use select() to handle two descriptors at once */
        maxfd = (tap_fd > net_fd)?tap_fd:net_fd;
        while(1)
        {
          int readLen=read(pipe_fd[0],combine, 100);
          combine[readLen]='\0';
          //printf("INwhile\n");
          if(readLen>0)
          {
            int k;
            for(k=0; k<KEY_IV_LENGTH;k++)
            {
              key[k]=combine[k+1];
              iv[k]=combine[KEY_IV_LENGTH+k+1];
            }
            //printf("Child Process: received Key (%s), IV (%s) \n", key, iv);
            usleep(1000);
            // get Notification
            readLen=read(pipe_fd[0],command,sizeof(command));
            command[readLen]='\0';
            if(command[0]=='o') OK=1;
            break;
          }
        }

        while(1) {
            int cmdLen=read(pipe_fd[0],command,strlen(command)+1);
            if(cmdLen>0) // if user has some inputs
            {
              //printf("Child process received command %s\n", command);
              if((command[0]== 'q' || command[0]=='Q'))
              {
                memset(key, 0x20, 16);memset(iv, 0x20, 16);
                _exit(0);
              }
              if((command[0]== 'k' || command[0]=='K'))
              {
                unsigned char temp[100];
                //int len=read(pipe_fd[0],temp,strlen(temp)+1);
                //printf("RRRead: %s, ReadLen: %d\n", temp, len);
                strncpy(temp,command,cmdLen-2); temp[cmdLen-1]='\0';
                int key_len=cmdLen-1<KEY_IV_LENGTH?cmdLen-1:KEY_IV_LENGTH;
                int idx;
                for(idx=0;idx<key_len;idx++)
                {
                  key[idx]=temp[idx];
                }
              }
              if ((command[0]== 'v' || command[0]== 'V'))
              {
                unsigned char temp[100];
                //int len=read(pipe_fd[0],temp,strlen(temp)+1);
                strncpy(temp,command,cmdLen-2); temp[cmdLen-1]='\0';
                int iv_len=cmdLen-1<KEY_IV_LENGTH?cmdLen-1:KEY_IV_LENGTH;
                int idx;
                for(idx=0;idx<iv_len;idx++)
                {
                  iv[idx]=temp[idx];
                }
              }
            }
          int ret;
          fd_set rd_set;
          FD_ZERO(&rd_set);
          FD_SET(tap_fd, &rd_set); FD_SET(net_fd, &rd_set);
          ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);

          if (ret < 0 && errno == EINTR){
            continue;
          }
          if (ret < 0) {
            perror("select()");
            exit(1);
          }
          if(FD_ISSET(tap_fd, &rd_set)){
            /* data from tun/tap: just read it and write it to the network */
            unsigned char buf_temp[BUFSIZE];
            nread = cread(tap_fd, buffer, BUFSIZE);
            do_debug("TAP2NET %lu: Read %d bytes from the tap interface\n", tap2net, nread);
            int cypher_len=encrypt(buffer, nread, key, iv, buf_temp);
            printf("Encrypted by using key: %s, IV: %s\n",key, iv);
            unsigned char* result_buf;
            int result_len=32;
            result_buf= malloc(sizeof(char)*(32+cypher_len));

            SHA256Hash(buf_temp, cypher_len, key, result_buf, &result_len);
            memcpy(result_buf+result_len, buf_temp, cypher_len);
            result_len= result_len+cypher_len;
            tap2net++;
          
            /* write length + packet */
            nwrite=sendto(net_fd, result_buf, result_len, 0,(struct sockaddr *)&remote,sizeof(remote));
            do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
          }

          if(FD_ISSET(net_fd, &rd_set)){
            /* data from the network: read it, and write it to the tun/tap interface. 
             * We need to read the length first, and then the packet */
            nread=recvfrom(net_fd,buffer,BUFSIZE,0,(struct sockaddr*)&remote, &remotelen);
            //printf("recvfrom: %s\n",buffer);
            do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);
            //do_debug("SERVER: Client connected from %s\n", inet_ntoa(client.sin_addr));
            if(nread == 0) 
            {
              /* ctrl-c at the other end */
              break;
            }
            
            net2tap++;
            unsigned char* hmac=malloc(32);
            unsigned char* data=malloc(BUFSIZE);
            memcpy(hmac, buffer, 32);
            memcpy(data, buffer+32, nread-32);
            //printf("hmac: %d, data: %d\n", strlen(hmac),strlen(data));
            if(HashVerify(data, nread-32, key, hmac))
            {
              unsigned char plaintext[BUFSIZE];
              int plain_len=decrypt(data, nread-32, key, iv, plaintext);
              printf("Decrypted by using key: %s, IV: %s\n",key, iv);
              /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
              nwrite = cwrite(tap_fd, plaintext, plain_len);
              do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
            }
            else
            {
              perror("ERROR: cannot verify");
              exit(1);
            }
          }
        }
        printf("jump out\n");
    }
  }
      
  return(0);
}
