#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <poll.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <time.h>
#include <ctype.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <signal.h>
#include "comBasic.h"
#include "sysapi.h"

#define MAXSERVERS	256
#define MAXCLIENTS	1024

#define AGENT_TYPE_AUTO			0
#define AGENT_TYPE_TCP			1
#define AGENT_TYPE_FTPControl	2
#define AGENT_TYPE_HTTP			5
#define AGENT_TYPE_ADMIN		6
#define AGENT_TYPE_GIOP			7
#define AGENT_TYPE_ZCRAW		8
#define AGENT_TYPE_TUNNEL		9

#define AGENT_TYPE_HEARTBEAT	10

#define AGENT_TYPE_HOSTED_TUNNEL	   309
#define AGENT_TYPE_HOSTING_TUNNEL      409

#define AGENT_TUNING_FORWARD       1
#define AGENT_TUNING_ACCEPT        2
#define AGENT_TUNING_HOSTED        3
#define AGENT_TUNING_HOSTING       4

#define AGENT_TYPE_TELNET		101
#define AGENT_TYPE_SSH			201
#define AGENT_TYPE_FTPPassive	301
#define AGENT_TYPE_FTPActive	401
#define AGENT_TYPE_SWITCHER	    501
#define AGENT_TYPE_SMTP			601
#define AGENT_TYPE_POP3			701
#define AGENT_TYPE_LDAP			801
#define AGENT_TYPE_ORACLE		901
#define AGENT_TYPE_SYBASE		1001
#define AGENT_TYPE_INFORMIX		1101
#define AGENT_TYPE_IMAP			1201
#define AGENT_TYPE_VNC          1301
#define AGENT_TYPE_WINTER	    1401

#define AGENT_TIMEOUT_MIN	60
#define AGENT_TIMEOUT_MAX   900
#define AGENT_FLOW_CONTROL	10

#define POLL_ERROR (POLLERR|POLLHUP|POLLNVAL)

struct agent_server_t {
  int sockfd;
  int resock;
  int type;
  int self;
  int timeout;
  int bind;
  int port;
  int tunnel;
  char from[16];
  char peer[32];
  char hostin[16];
  char hostout[16];
  struct agent_client_t *client;
  char *text;
  int logging;
  int holding;
  int idle;
  int single;
  int tuning;
  char ext[64+1];
};

struct agent_client_t {
  int running;
  int type; 
  int self;
  int timeout;
  int admin; // 0-no admin 1-intl admin 2-admin
  int status;
  int sockin;
  int sockout;
  int conntv;
  int sendsize;
  int readsize;
  int ssize;
  int rsize;
  int idle;
  int bind;
  int port;
  int dest;
  int tunnel;
  int tuning;
  char peer[16];
  char peerout[16];
  char peerto[16];
  char hostin[16];
  char hostout[16];
  pthread_t tid;
  struct agent_server_t *server;
  struct agent_server_t *forward;
  int logging;
  int logind;
  int welcome;
  int single;
  FILE *log;
};

static struct agent_server_t servers[MAXSERVERS];
static struct agent_client_t clients[MAXCLIENTS];
static char *config;
static char *nullstr = "";

static int numserver = 0;
static int numclient = 0;
static int locked = 0;

static void check_agent_local(struct agent_server_t *s)
{
  s->self = s->bind == s->port && !strcmp(s->peer, "127.0.0.1");
  if(s->type%100 != 9) s->tuning = 0;
  else if(s->type == 9) s->tuning = s->self ? 2 : 1;
  else if(s->type == 309) s->tuning = 3;
  else if(s->type == 409) s->tuning = 4;
}

static int check_server_local(struct agent_client_t *client, struct agent_server_t *s)
{
  if(!strcmp(s->peer, "127.0.0.1")) return 1;
  if(!strcmp(s->peer, client->hostin)) return 1;
  if(!strcmp(s->peer, client->hostout)) return 1;
  s->self = 0;
  return 0;
}

static struct agent_server_t *check_client_local(struct agent_client_t *client, struct agent_server_t *s)
{
int i;
  if(!check_server_local(client, s)) { s->self = 0; return s; }
  for(i=0;i<numserver;i++) if(servers[i].bind == s->port) {
    s = servers + i;
	if(s->self) return s;
    return check_client_local(client, s);
  }
  s->self = 0;
  return s;
}

static int str2type(char *s)
{
  if(!strcasecmp(s, "FTP")) return 2;
  else if(!strcasecmp(s, "HTTP")) return 5;
  else if(!strcasecmp(s, "ADMIN")) return 6;
  else if(!strcasecmp(s, "ADM")) return 6;
  else if(!strcasecmp(s, "GIOP")) return 7;
  else if(!strcasecmp(s, "IIOP")) return 7;
  else if(!strcasecmp(s, "CORBA")) return 7;
  else if(!strcasecmp(s, "ORB")) return 7;
  else if(!strcasecmp(s, "ZCRAW")) return 8;
  else if(!strcasecmp(s, "RAW")) return 8;
  else if(!strcasecmp(s, "TUNNEL")) return 9;
  else if(!strcasecmp(s, "TELNET")) return 101;
  else if(!strcasecmp(s, "SSH")) return 201;
  else if(!strcasecmp(s, "SWITCHER")) return 501;
  else if(!strcasecmp(s, "SWITCH")) return 501;
  else if(!strcasecmp(s, "SMTP")) return 601;
  else if(!strcasecmp(s, "POP3")) return 701;
  else if(!strcasecmp(s, "POP")) return 701;
  else if(!strcasecmp(s, "LDAP")) return 801;
  else if(!strcasecmp(s, "ORACLE")) return 901;
  else if(!strcasecmp(s, "SYBASE")) return 1001;
  else if(!strcasecmp(s, "INFORMIX")) return 1101;
  else if(!strcasecmp(s, "IMAP")) return 1201;
  else if(!strcasecmp(s, "VNC")) return 1301;
  else if(!strcasecmp(s, "WINTERM")) return 1401;
  else if(!strcasecmp(s, "DESKTOP")) return 1401;
  else if(!strcasecmp(s, "HOSTING")) return 409;
  else if(!strcasecmp(s, "HOSTED")) return 309;
  else if(!strcasecmp(s, "AUTO")) return 0;
  else if(*s) return 1;
  else return 0;
}

static char *type2str(int type)
{
  if(type==0) return "auto";
  else if(type==1) return "tcp";
  else if(type==2) return "ftp";
  else if(type==5) return "http";
  else if(type==6) return "admin";
  else if(type==7) return "iiop";
  else if(type==8) return "zcraw";
  else if(type==9) return "tunnel";
  else if(type==101) return "telnet";
  else if(type==201) return "ssh";
  else if(type==301) return "ftpU";
  else if(type==401) return "ftpD";
  else if(type==501) return "switcher";
  else if(type==601) return "smtp";
  else if(type==701) return "pop3";
  else if(type==801) return "ldap";
  else if(type==901) return "oracle";
  else if(type==1001) return "sybase";
  else if(type==1101) return "informix";
  else if(type==1201) return "imap";
  else if(type==1301) return "vnc";
  else if(type==1401) return "winterm";
  else if(type==309) return "hosted";
  else if(type==409) return "hosting";
  else return "tcp";
}

static int trylock()
{
int i;
  for(i=0;i<100;i++) {
    if(locked==0) if(locked==0) { locked=1; return 0; } 
	poll(NULL,0,50);
  }
  return -1;
}

static void set_agent_text(struct agent_server_t *s, char *text)
{
  if(!text) s->text = nullstr;
  else if(*text=='\0') s->text = nullstr;
  else {
    strncpy(s->ext, text, 64);
	s->ext[64] = '\0';
	s->text = s->ext;
  }
}

static struct agent_server_t *find_tunnel_server(int tunnel)
{
struct agent_server_t *s;
  if(!tunnel) return NULL;
  for(s = servers; s < servers + numserver; s++)
    if(s->bind==tunnel && s->type%100==9) return s;
  return NULL;
}

static struct agent_server_t *new_agent_server(struct agent_server_t *server)
{
struct agent_server_t *s, *s1, *clone;
char buf[16+1];
int ret;
  trylock();
  for(s = servers, s1 = clone = NULL; s < servers + numserver; s++) {
    if(s->bind == server->bind && server->bind != -1) {
	  if(!strcmp(s->from, server->from) && s->holding!=2) { locked=0; return NULL;  }
	  if(!clone) clone = s;
	}
    if(! s->bind) s1 = s;
  }
  if(!s1) if(numserver == MAXSERVERS) { locked=0; return NULL; }
  s = s1 ? s1 : servers + numserver;
  s->sockfd = -1;
  s->resock = -1;
  if(! clone && server->bind>19 && server->type!=409) {
    sprintf(buf, "%d", server->bind);
    output(11, "\n%s$%d : Listening on port %d ...", AppName, s - servers, server->bind);
    ret = serListen(AF_INET, buf, &(s->sockfd));
    output(1, "%s.", ret < 0 ? "Failure" : "Success");
    if(ret < 0) { locked=0; return NULL; }
  }
  s->bind = server->bind;
  s->type = server->type;
  s->self = server->self;
  strcpy(s->peer, server->peer);
  strcpy(s->from, server->from);
  strcpy(s->hostin, server->hostin);
  strcpy(s->hostout, server->hostout);
  s->port = server->port;
  s->tunnel = server->tunnel;
  s->client = server->client;
  s->holding = clone != NULL;
  s->timeout = server->timeout;
  set_agent_text(s, server->text);
  s->logging = server->logging;
  s->idle = 0;
  s->single = server->single;
  s->tuning = server->tuning;
  if(!s1) numserver++;
  locked = 0;
  output(11, "\n%s$%d : Agent server forked for %d ==> %s : %d", AppName, s - servers, s->bind<0 ? 0 : s->bind, s->peer, s->port);
  return s;
}

static void end_agent_server(struct agent_server_t *s)
{
int j;
  output(11, "\n%s$%d : Agent server exited for %d ==> %s : %d", AppName, s - servers, s->bind<0 ? 0 : s->bind, s->peer, s->port);
  trylock();
  s->bind = 0;
  if(s->sockfd != -1) closesocket(s->sockfd);
  if(s->resock != -1) closesocket(s->resock);
  s->client = NULL;
  s->sockfd = -1;
  s->resock = -1;
  s->text = nullstr;
  for(j=numserver;j>0;j--) if(servers[j-1].bind) break;
  numserver = j;
  locked = 0;
}

static void end_ftp_client(struct agent_client_t *client)
{
int j;
struct agent_server_t *s;
  for(;;) {
    trylock();
    for(j=0,s=servers;j<numserver;j++,s++) if(s->bind!=-1 && s->client == client) break;
    if(j==numserver) { locked=0; break; }
	locked = 0;
	end_agent_server(s); 
  }
}

static struct agent_server_t *try_agent_server(struct agent_server_t *server)
{
int i;
struct agent_server_t *s;
  for(i=0;i<32;i++) {
	if(server->bind>65535) return NULL;
	s = new_agent_server(server);
	if(s) return s;
	server->bind++;
  }
  return NULL;
}

static struct agent_server_t *try_iiop_server(struct agent_server_t *server)
{
struct agent_server_t *s;
  trylock();
  for(s = servers; s < servers + numserver; s++) {
    if(s->bind && s->port == server->port) if(!strcmp(s->peer, server->peer)) { locked=0; return s; }
  }
  locked = 0;
  return try_agent_server(server);
}

struct frame_t {
  int method;
  char *proto;
  char *user;
  char *pass;
  char *host;
  char *port;
  char *url;
  char *uri;
  char *arg;
  char *version;
  char *line;
  char *buff;
  int length;
  int endian;
  int size;
  int max;
};

//==0 : Continue 
//> 0 : line length
//< 0 : not text line

static void initline(struct frame_t *ln, char *buff, int max)
{
  ln->buff = buff;
  ln->max = max;
  ln->size = 0;
  ln->line = buff;
  ln->method = 0;
  ln->length = 0;
}

static int checkline(char *buff, char *pend)
{
char *p;
  for(p=buff;p<pend;p++) {
    if(*p=='\n') return p + 1 - buff;
    if(*p=='\r' || *p=='\t') continue;
	if(*p>=0 && *p<' ') return -1;
  }
  return 0;
}

static int addline(struct frame_t *h, char *buff, int size)
{
int r1, r2;
   if(h->size + size > h->max) return -1;
   r1 = checkline(h->line, h->buff + h->size);
   if(r1 < 0) return -1;
   if(!size) return r1;
   r2 = r1 ? 0 : checkline(buff, buff+size);
   if(r2 < 0) return -1;
   if(size) memcpy(h->buff + h->size, buff, size);
   h->size += size;
   if(r1) return r1;
   if(!r2) return 0;
   r1 = checkline(h->line, h->buff + h->size);
   return r1;
}

static void skipline(struct frame_t *h, int size)
{
  h->line += size;
}

static void eatline(struct frame_t *ln, int size)
{
  ln->size -= size;
  ln->line = ln->buff;
  if(ln->size) memmove(ln->buff, ln->buff+size, ln->size);
}

static int addraw(struct frame_t *r, char *buff, int size)
{
  if(r->size + size > r->max) return -1;
  if(size) memcpy(r->buff + r->size, buff, size);
  r->size += size;
  return 0;
}

static void eatraw(struct frame_t *r, int size)
{
  r->size -= size;
  if(r->size) memcpy(r->buff, r->buff+size, r->size);
}

static int orb_get_int(char *buff, int endian)
{
unsigned char *p = (unsigned char *)buff;
  if(endian) return p[0] | (p[1]<<8) | (p[2]<<16) | (p[3]<<24);
  else return p[3] | (p[2]<<8) | (p[1]<<16) | (p[0]<<24);
}

static int orb_get_word(char *buff, int endian)
{
unsigned char *p = (unsigned char *)buff;
  if(endian) return p[0] | (p[1]<<8);
  else return p[1] | (p[0]<<8);
}

static void orb_set_int(int v, char *buff, int endian)
{
  if(endian) { 
    buff[0] = v&0xff;
	buff[1] = (v>>8)&0xff;
	buff[2] = (v>>16)&0xff;
	buff[3] = (v>>24)&0xff;
  }
  else {
    buff[3] = v&0xff;
	buff[2] = (v>>8)&0xff;
	buff[1] = (v>>16)&0xff;
	buff[0] = (v>>24)&0xff;
  }
}

static void orb_set_word(int v, char *buff, int endian)
{
  if(endian) { 
    buff[0] = v&0xff;
	buff[1] = (v>>8)&0xff;
  }
  else {
    buff[1] = v&0xff;
	buff[0] = (v>>8)&0xff;
  }
}

static int addgiop(struct frame_t *g, char *buff, int size)
{
  if(g->length && size > g->length) return -1;
  if(!g->size && g->length) {  g->length -= size;	return -2;    }
  if(g->size + size > g->max) size = g->max - g->size;
  if(size) memcpy(g->buff + g->size, buff, size);
  g->size += size;
  g->buff[g->size] = '\0';
  if(g->size < 4) return 0;
  if(strncmp(g->buff, "GIOP", 4)) { g->size-=size; return -1; }
  if(g->size < 12) return 0;
  if(!g->length) {
    g->endian = g->buff[6];
    g->method = g->buff[7];
    g->length = orb_get_int(g->buff+8, g->endian);
	if(g->length < 0) { g->size-=size; return -1; }
	g->length += 12;
  }
  if(g->size < g->length && g->length < g->max) return 0;
  g->line = g->buff + g->size;
  return size;
}

static void eatgiop(struct frame_t *g)
{
  g->length -= g->size;
  g->size = 0;
}

static int check_giop_ior(struct frame_t *g)
{
int i,n,size,ret;
char *p;
  i = 0; p = g->url; size = g->line - g->url;
  ret = orb_get_int(p+i, g->endian);		//IDL type_id string length(4)
  if(ret<1 || i+4+ret > size) return 0;
  n = strlen(p+i+4)+1;						//IDL type_id string(n)
  if(n != ret) return 0;
  if(strncmp(p+i+4, "IDL:", 4)) return 0;
  i+=4+n; if(i%4) i=i-i%4+4;
  if(i+4 > size) return 0;
  ret = orb_get_int(p+i, g->endian);		//Sequence length(4)
  if(ret < 1 || ret > 16) return 0;
  i+=4;  if(i+4 > size) return 0;			//Profile ID(4) == 0
  ret = orb_get_int(p+i, g->endian);
  if(ret != 0) return 0;
  i+=4;  if(i+4 > size) return 0;			
  ret = orb_get_int(p+i, g->endian);		//Sequence length(4)
  if(ret<1 || i+4+ret > size) return 0;
  g->arg = p+i;
  i+=7;  if(i%4) i=i-i%4+4;					//Endianess(1) + Major(1) + Minor(1)
  if(i+4 > size) return 0;
  ret = orb_get_int(p+i, g->endian);		//Profile_host string length(4)
  if(ret<1 || i+4+ret > size) return 0;
  n = strlen(p+i+4)+1;						//Profile_host string(n)
  if(n != ret) return 0;
  if(n > 16) return 0;
  g->host = p+i+4;
  i+=4+n; if(i%2) i=i-i%2+2;
  if(i+2 > size) return 0;
  g->port = p+i;							//Profile_port(2)
  i+=2; if(i%4) i=i-i%4+4;
  if(i+4 > size) return 0;
  g->uri = p+i;
  return 1;
}

static int check_giop_reply(struct frame_t *g)
{
int size;
char *p;
  if(g->method != 1) return 0;
  if(g->length != g->size) return 0;
  size = g->length - 12;
  p = g->buff + 12;
  if(size <= 12) return 0;
  g->url = p + 12; 
  return check_giop_ior(g);
}

static int encode_ftp_address(char *line, char *peer, int port)
{
int len = 0;
char *p;
  strcpy(line, peer);
  for(p=line;*p;p++) if(*p=='.') *p=',';
  len += p - line;
  len += sprintf(p, ",%d,%d", port/256, port%256);
  return len;
}

static int decode_ftp_address(char *line, char endchar, struct agent_server_t *s)
{
char *p;
int x[4];
  x[0] = strtol(line, &p, 10);
  if(p==line || *p != ',') return -1;
  if(x[0]<0 || x[0]>255) return -1;
  line=p+1; x[1] = strtol(line, &p, 10);
  if(p==line || *p != ',') return -1;
  if(x[1]<0 || x[1]>255) return -1;
  line=p+1; x[2] = strtol(line, &p, 10);
  if(p==line || *p != ',') return -1;
  if(x[2]<0 || x[2]>255) return -1;
  line=p+1; x[3] = strtol(line, &p, 10);
  if(p==line || *p != ',') return -1;
  if(x[3]<0 || x[3]>255) return -1;
  sprintf(s->peer, "%d.%d.%d.%d", x[0], x[1], x[2], x[3]);
  line=p+1; x[0] = strtol(line, &p, 10);
  if(p==line || *p != ',') return -1;
  if(x[0]<0 || x[0]>255) return -1;
  line=p+1; x[1] = strtol(line, &p, 10);
  if(p==line) return -1;
  if(endchar) { if(*p != endchar) return -1; else p++;  }
  if(*p=='.') p++;
  if(*p=='\r') p++;
  if(*p!='\n') return -1;
  if(x[1]<0 || x[1]>255) return -1;
  s->port = x[0]*256 + x[1];
  return 0;
}

static int check_ftp_active(char *line, struct agent_server_t *s)
{
  if(strncasecmp(line, "PORT ", 5)) return 0;
  line += 5;
  if(decode_ftp_address(line, 0, s)<0) return -1;
  return 1;
}

static int check_ftp_passive(char *line, struct agent_server_t *s)
{
  if(strncmp(line, "227 ", 4)) return 0;
  line = strchr(line, '(');
  if(!line) return -1;
  if(decode_ftp_address(line+1, ')', s)<0) return -1;
  return 1;
}

static int check_ftp_welcome(char *line)
{
  if(strncmp(line, "220", 3)) return 0;
  if(line[3]!=' ' && line[3]!='-') return 0;
  return 1;
}

static int decode_proxy_address(char *line, struct frame_t *h, char *buff)
{
char *p, *q;
int n;
  for(p=line,q=NULL;*p && *p!=':' && *p!=' ' && *p!='\r' && *p!='\n';p++)
    if(*p=='@') q = p;
  if(!q && !h->host) return 0;
  if(q) {  h->user = line;   h->host = q+1;  }
  if(*p==':' || *p==' ') h->port = p+1;
  if(h->user) {
    q = strchr(h->user, ':');
	if(q > h->host) q = NULL;
	if(q) h->pass = q + 1;
  }
  if(h->user) {
    n = h->pass ? h->pass - h->user - 1 : h->host - h->user - 1;
	if(n>64) n = 64;
	strncpy(buff, h->user, n);
	buff[n]='\0';
	h->user = buff;
	buff += n+1;
  }
  if(h->pass) {
    n = h->host - h->pass - 1;
	if(n>64) n = 64;
	strncpy(buff, h->pass, n);
	buff[n]='\0';
	h->pass = buff;
	buff += n+1;
  }
  n = p - h->host;
  if(n<1 || n>15) return 0;
  strncpy(buff, h->host, n); 
  buff[n]='\0'; 
  h->host = buff;
  buff += n+1;
  if(h->port) {
    for(q=h->port;*q && *q!=' ' && *q!='\r' && *q!='\n';q++);
	n = q - h->port;
	if(n>15) return 0;
	strncpy(buff, h->port, n);
	buff[n]='\0';
	h->port = buff;
	buff += n+1;
  }
  return 1;
}

static char *nextstr(char *line, char *s, int max)
{
char *p;
int n;
  for(p=line;*p==' ';p++);
  for(line=p;*p && *p!=' ' && *p!='\r' && *p!='\n';p++);
  n = p - line;
  if(n>max) n = max;
  strncpy(s, line, n);
  s[n] = '\0';
  return p;
}

static int check_ftp_proxy(char *line, struct frame_t *h, char *buff)
{
int ret;
char *p;
  h->host = NULL;
  h->port = NULL;
  h->user = NULL;
  h->pass = NULL;
  if(!strncasecmp(line, "OPEN ", 5)) {
    h->host = line+5;
    return decode_proxy_address(line+5, h, buff);
  }
  if(!strncasecmp(line, "SITE ", 5)) {
    h->host = line+5;
    return decode_proxy_address(line+5, h, buff);
  }
  if(!strncasecmp(line, "USER ", 5)) {
    ret = decode_proxy_address(line+5, h, buff);
	if(ret) if(!h->user) ret = 0;
	if(ret) return 1;
    p = nextstr(line+5, buff, 64);
	h->user = buff;
	buff += strlen(buff)+1;
	if(*p=='\0' || *p=='\r' || *p=='\n') return 2;
	p = nextstr(p+1, buff, 64);
	h->pass = buff;
	buff += strlen(buff)+1;
	return 3;
  }
  if(!strncmp(line, "PASS ", 5)) {
    p = nextstr(line+5, buff, 64);
	h->pass = buff;
	buff += strlen(buff)+1;
	return 4;
  }
  if(!strncmp(line, "QUIT", 4)) {
    p = line+4;
	if(*p=='\0' || *p==' ' || *p=='\r' || *p=='\n') return 5;
  }
  return 0;
}

static int check_http_request(char *line, char *end, struct frame_t *h)
{
char *p, *q;
  if(!strncasecmp(line, "GET ", 4)) { line+=4; h->method = 1; }
  else if(!strncasecmp(line, "POST ", 5)) { line+=5; h->method = 2; }
  else if(!strncasecmp(line, "HEAD ", 5)) { line+=5; h->method = 3; }
  else if(!strncasecmp(line, "PUT ", 4)) { line+=4; h->method = 4; }
  else return 0;
  h->url = line;
  p = strstr(line, "HTTP/");
  if(!p || p>end) return 0;
  if(p[-1] != ' ') return 0;
  h->version = p;
  for(p+=5;*p>='0' && *p<='9';p++);
  if(*p=='.') for(p++;*p>='0' && *p<='9';p++);
  if(*p=='\r') p++;
  if(*p!='\n') return 0;
  h->proto = NULL;
  h->user = NULL;
  h->pass = NULL;
  h->uri = h->url;
  h->host = NULL;
  h->port = NULL;
  h->arg = NULL;
  p = strstr(h->url, "://");
  if(p && p<h->version) {
    h->proto = h->url;
    h->host = p + 3;
    p = strchr(h->host, '/');
	if(q >= h->version) p = NULL;
	h->uri = p;
	p = strchr(h->host, '@');
	if(p>h->uri) p = NULL;
	if(p) {
	  h->user = h->host;
	  h->host = p + 1;
	  p = strchr(h->user, ':');
	  if(p > h->host) p = NULL;
	  if(p) h->pass = p + 1;
	}
	p = strchr(h->host, ':');
	if(p>h->uri) p = NULL;
	if(p) h->port = p + 1;
  }
  if(h->uri) {
    for(p=h->uri, q=NULL;p<h->version;p++) if(*p=='/') q = p+1;
    if(q) p = strchr(q, '?');
	if(q && p && p < h->version) h->arg = p + 1;
  }
  return 1;
}

static int check_http_hostname(char *line, char *end, struct frame_t *h)
{
char *p;
  if(strncasecmp(line, "HOST:", 5)) return 0;
  h->host = line + 6;
  p = strchr(h->host, ':');
  if(p > end) p = NULL;
  if(p) h->port = p+1;
  return 1;
}

static int check_http_head_over(char *line)
{
  if(*line=='\r') line++;
  return *line == '\n';
}

static int check_self_request(struct agent_client_t *client, struct frame_t *h)
{
int n;
char ch;
  if(h->port) {
    if(atoi(h->port) != client->bind) return 0;
  }
  else {
    if(client->bind != 80) return 0;
  }
  if(h->host) {
    n = strlen(client->hostin);
    if(strncmp(h->host, client->hostin, n)) return 0;
	ch = h->host[n];
	if(ch!=':' && ch!='\r' && ch!='\n') return 0;
  }
  return 1;
}

static int check_sock_request(struct agent_client_t *client, struct frame_t *h)
{
char ch;
  if(client->type != 6) if(!check_self_request(client, h)) return 0;
  if(!h->uri) return 0;
  if(strncmp(h->uri, "/socks", 6)) return 0;
  ch = h->uri[6];
  if(ch != ' ' && ch != '?') return 0;
  return 1;
}

static int handle_sock_request(struct agent_client_t *client, struct frame_t *h, struct agent_server_t *ser);

static int check_raw_request(struct frame_t *h, struct agent_server_t *s)
{
unsigned char *p;
  if(h->size < 12) return 0;
  p = (unsigned char *)(h->buff);
  if(p[0]<10) return -1;
  if(p[1]==255) return -1;
  if(p[2]==255) return -1;
  if(p[3]==0 || p[3]==255) return -1;
  if(p[4]>0) return -1;
  if(p[5]>0) return -1;
  sprintf(s->peer, "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
  s->port = orb_get_int(p+4, 0);
  if(s->port<1024 || s->port>65535) return -1;
  return 1;
}

static int open_radius_connection(struct agent_client_t *client, struct agent_server_t *ser)
{
int waiting=0;
  while(client->running && waiting<300) {
    if(trylock()<0) { waiting+=50; continue; }
    if(ser->resock != -1) {
      client->sockout = ser->resock;
      ser->resock = -1;
      locked = 0;
      break;
    }
    locked = 0;
    poll(NULL, 0, 100);
    waiting++;
  }
  if(client->sockout < 0) return -1;
  client->self = 0;
  if(client->hostout[0]=='\0') PrintHostAddress(client->sockout, client->hostout);
  strcpy(client->peerout, ser->peer);
  client->port = ser->port;
  return 0;
}

static int open_remote_connection(struct agent_client_t *client, struct agent_server_t *ser, int self)
{
char s[32+1];
int ret, sockfd;
  ser = check_client_local(client, ser);
  client->self = ser->self;
  if(client->self && !self) return -1;
  if(client->self) strcpy(client->peerout, ser->peer);
  else {
    output(11, "\n%s#%d : Connecting from client %s : %d to %s : %d...", AppName, client->tid, client->peer, client->bind, ser->peer, ser->port);
    sprintf(s, "%d", ser->port);
    client->forward = ser;
    client->status = 10;
    ret = cliConnect(AF_INET, ser->peer, s, &sockfd);
    client->status = 0;
    output(1, "%s.", ret < 0 ? "Failure" : "Success");
    if(ret<0) return -1;
    client->sockout = sockfd;
	PrintPeerAddress(client->sockout, client->peerout);
    if(client->hostout[0]=='\0') PrintHostAddress(client->sockout, client->hostout);
  }
  
  client->port = ser->port; 
  if(client->hostout[0]=='\0') strcpy(client->hostout, client->hostin);
  return 0;
}

static int open_http_connection(struct agent_client_t *client, struct frame_t *h)
{
struct agent_server_t as;
char *p;
int n;
  if(!h->host) return -1;
  as.port = h->port ? atoi(h->port) : 80;
  for(p=h->host;*p && *p!=':' && *p!='\r' && *p!='\n';p++);
  n = p - h->host;
  strncpy(as.peer, h->host, n);
  as.peer[n] = '\0';
  return open_remote_connection(client, &as, 0);
}

static int open_ftp_connection(struct agent_client_t *client, struct agent_server_t *ser)
{
int ret, sockfd;
  sockfd = client->sockout;
  ret = open_remote_connection(client, ser, 0);
  if(ret) return -1;
  if(sockfd>=0) closesocket(sockfd);
  return 0;
}

static int open_raw_connection(struct agent_client_t *client, struct agent_server_t *ser)
{
  return open_remote_connection(client, ser, 0);
}

static int orb_encode_address(char *buff, struct frame_t *g, char *host, int port)
{
int i, r1, r2;
  i = g->host - g->buff;
  r1 = strlen(g->host) + 1;
  r2 = strlen(host) + 1;
  if(r1 == r2) {
    memcpy(buff, g->buff, g->size);
    strcpy(buff + i, host);
	i = g->port - g->buff;
	orb_set_word(port, buff + i, g->endian);
	return g->size;
  }
  memcpy(buff, g->buff, i);
  orb_set_int(r2, buff + i - 4, g->endian);
  strcpy(buff + i, host);
  i += r2; if(i%2) i=i+2-i%2;
  orb_set_word(port, buff + i, g->endian);
  i += 2;  if(i%4) i=i+4-i%4;
  r1 = g->uri - g->buff;
  r2 = g->size - r1;
  memcpy(buff + i, g->buff + r1, r2);
  i += r2;
  orb_set_int(i-12, buff + 8, g->endian);
  r1 = g->arg - g->buff;
  r2 = orb_get_int(g->arg, g->endian);
  orb_set_int(r2 + i - g->size, buff + r1, g->endian);
  return i;
}

static int socksend(int sockfd, char *buff, int size)
{
int ret;
    ret = send(sockfd, buff, size, 0);
    if(ret<0) if(errno==EINTR) ret = send(sockfd, buff, size, 0);
	return ret;
}

static int sock_vprintf(int sockfd, int size, const char *fmt, va_list arg)
{
char buff[size+1];
int ret;
  ret = vsnprintf(buff, size, fmt, arg);
  if(ret > size) return ret;
  return socksend(sockfd, buff, ret);
}

static int sock_printf(int sockfd, const char *fmt, ...)
{
va_list arg;
int ret;
  va_start(arg, fmt);
  ret = sock_vprintf(sockfd, 1024, fmt, arg);
  if(ret > 1024) ret = sock_vprintf(sockfd, ret, fmt, arg);
  va_end(arg);
  return ret;
}

static void client_write_log(struct agent_client_t *client, int ind, char *buff, int size)
{
char s[256+1], *p;
int i,n;
struct timeval tv;
  if(!client->logging || !size) return;
  if(!client->log) {    
    p = s + sprintf(s, "socks.log_%s_%s:%d_", client->peer, client->hostin, client->port);
	sprintt(p, client->conntv);
	for(i=0;p[i];i++) if(p[i]==' ') p[i]=':';
	client->log = fopen(s, "wb");
	if(!client->log) return;
  }
  if(ind != client->logind) {
    gettimeofday(&tv, NULL);
	sprintt(s, tv.tv_sec);
	fprintf(client->log, "%s.%03d : ", s, tv.tv_usec/1000);
	switch(ind) {
	  case 1 : fprintf(client->log, "%s.%d ==> %s.%d",  client->peer, 0, client->hostin, client->bind); break;
	  case 2 : fprintf(client->log, "%s.%d ==> %s.%d",  client->hostout, client->bind, client->peerout, client->port); break;
	  case 3 : fprintf(client->log, "%s.%d <== %s.%d",  client->hostout, client->bind, client->peerout, client->port); break;
	  case 4 : fprintf(client->log, "%s.%d <== %s.%d",  client->peer, 0, client->hostin, client->bind); break;
	}
	client->logind = ind;
	fprintf(client->log, " len = %d\n", size);
  }
  for(;size>0;size-=n, buff+=n) {
    n = size > 32 ? 32 : size;
	for(i=0, p=s;i<32;i++) {
	  if(i%8==0) *p++ = ' ';
	  if(i<n) p += sprintf(p, " %02x", (unsigned char)buff[i]);
	  else { strcpy(p, "   "); p+=3; }
	}
	strcpy(p, "  "); p+=2;
	for(i=0;i<n;i++) *p++ = isprint(buff[i]) ? buff[i] : '.';
	*p = '\0';
	fprintf(client->log, "%s\n", s+2);
  }
  client->logging = 2;
}

static void client_flush_log(struct agent_client_t *client)
{
  if(!client->log || client->logging!=2) return;
  fflush(client->log);
  client->logging = 1;
}

static int send_ftp_welcome(struct agent_client_t *client)
{
char buff[1024+1];
int ret;
  if(client->type != 2 || !client->self) return 0;
  if(client->admin == 1) return 0;
  if(client->welcome != 1) return 0;
  ret = sprintf(buff, "220 Socks FTP Proxy Ready.\r\n");
  client_write_log(client, 4, buff, ret);
  socksend(client->sockin, buff, ret);
  client->welcome = 0;
  return 1;
}

static int skip_ftp_welcome(struct agent_client_t *client, char *line, int len)
{
  if(client->type != 2) return 0;
  if(client->welcome != 2) return 0;
  if(strncmp(line, "220", 3)) { client->welcome = 0; return 0; }
  if(line[3]!='-' && line[3]!=' ') { client->welcome = 0; return 0; }
  client_write_log(client, 3, line, len);
  if(line[3]=='-') return 1;
  client->welcome = 0;
  return 1;
}

static int send_telnet_prompt(struct agent_client_t *client)
{
char buff[256+1];
int ret;
  if(client->type != 101 || !client->self) return 0;
  if(client->admin == 1) return 0;
  if(client->welcome != 1) return 0;
  ret = sprintf(buff, "Host: ");
  client_write_log(client, 4, buff, ret);
  socksend(client->sockin, buff, ret);
  client->welcome = 0;
  return 1;
}

static int check_telnet_prompt(struct agent_client_t *client, struct frame_t *h, int size)
{
int i,n,ch,ret;
char buff[1024+1];
char *p;
  for(n=0,i=h->size-size;i<h->size;i++) {
    ch = h->buff[i];
	if(ch==0x08 || ch==0x7f) { buff[n++] = 0x08; buff[n++] = 0x20; buff[n++] = 0x08; }
	else if(ch=='\0') buff[n++] = 0x0a;
	else buff[n++] = ch;
  }
//  client_write_log(client, 4, buff, n);
//  socksend(client->sockin, buff, n);
  if(h->size < 2) return 0;
  for(i=0;i<h->size;i++) if(h->buff[i]==0x0d) break;
  if(i > 256) return -1;
  if(i+1>=h->size) return 0;
  ch = h->buff[i+1];
  if(ch != 0x00 && ch != 0x0a) return 0;
  ret = i + 2;
  for(i=n=0;i<ret;i++) {
    ch = h->buff[i];
	if(ch==0x08 || ch==0x7f) { if(n) n--; } 
	else if(ch>=' ') h->buff[n++] = ch;
  }
  h->buff[n] = '\0';
  h->host = NULL;
  h->port = NULL;
  if(!n) { client->welcome = 1; return ret; }
  for(p=h->buff;*p>' ' && *p!=':';p++);
  if(p == h->buff) return -1;
  if(*p) *p++='\0';
  for(;*p>0 && *p<=' ';p++);
  h->host = h->buff;
  if(*p) h->port = p;
  return ret;
}

struct tunnel_head_t {
  char ident[8];
  int size;
  int version;
  int type;
  char peer[16];
  int port;
};

static int check_tunnel_request(char *buff, int size, struct agent_server_t *ser)
{
struct tunnel_head_t *h;
int i,ret;  
  if(size < 40) return 0;
  h = (struct tunnel_head_t *)(buff);
  if(strcmp(h->ident, "socktnl")) return -1;
  ret = ntohl(h->size);
  if(ret < 40 || ret > 256) return -1;
  if(size < ret) return 0;
  h->version = ntohl(h->version);
  if(h->version <= 0x20100601 && ret > 40) return -1;
  ser->type = ntohl(h->type);
  if(ser->type <= 0) return -1;
  for(i=0;i<16;i++) if(h->peer[i]=='\0') break;
  if(i==16) return -1;
  strcpy(ser->peer, h->peer);
  ser->port = ntohl(h->port);
  if(ser->port <= 0 || ser->port > 65535) return -1;
  return ret;
}

static int send_tunnel_request(struct agent_client_t *client, int sockfd, struct agent_server_t *ser)
{
int ret;
char buff[256+1];
struct tunnel_head_t *h;
  ret = sizeof(struct tunnel_head_t);
  h = (struct tunnel_head_t *)buff;
  strcpy(h->ident, "socktnl");
  h->size = htonl(ret);
  h->version = htonl(0x20100601);
  h->type = htonl(ser->type);
  strcpy(h->peer, ser->peer);
  h->port = htonl(ser->port);
  if(client) client_write_log(client, 2, buff, ret);
  return socksend(sockfd, buff, ret);
}

static int open_tunnel_connection(struct agent_client_t *client, struct agent_server_t *ser, int tunnel)
{
int ret;
struct agent_server_t *tun, as;

  tun = find_tunnel_server(tunnel);
  if(tun) if(tun->tunnel) tun = find_tunnel_server(tun->tunnel);
  if(!tun) return -1;
  if(tun->tuning==4) {
    ret=open_remote_connection(client, ser, 1);
    if(ret<0) return -1;
  }
  else if(tun->tuning==3) {
    ret = open_radius_connection(client, tun);
    if(ret < 0) return -1;
    send_tunnel_request(client, client->sockout, ser);
  }
  else if(tun->tuning==2) {
    ret=open_remote_connection(client, ser, 1);
    if(ret<0) return -1;
  }
  else if(check_server_local(client, ser)) {
    ret=open_remote_connection(client, ser, 1);
    if(ret<0) return -1;
  }
  else {
    ret=open_remote_connection(client, tun, 0);
    if(ret<0) return -1;
    send_tunnel_request(client, client->sockout, ser);
  }
  if(strcmp(ser->peer, client->peerout) || ser->port != client->port) {
    strcpy(client->peerto, ser->peer);
    client->dest = ser->port;
  }
  client->type = ser->type;
  client->admin = 0;
  if(client->self) if(client->type == 5 || client->type == 6) client->admin = 2;
  client->welcome = client->self;
  return 0;
}

static int client_wait_turn(struct agent_client_t *client)
{
int i,n;
struct agent_client_t *cli;
  if(! client->single) return 0;
  for(n=0;client->running && n<9000;n++) {
    for(i=0, cli=clients;i<numclient;i++, cli++) 
	  if(cli != client && cli->running && cli->bind == client->bind) break;
	if(i==numclient) return 0;
	client->status = 7;
	poll(NULL, 0, 100);
  }
  return -1;
}

static int open_client_connection(struct agent_client_t *client, struct agent_server_t *as)
{
  if(client->tuning) return -1;
  if(client->tunnel)
    return open_tunnel_connection(client, as, client->tunnel);
  return open_remote_connection(client, as, 1);
}

static int handle_radius_request(struct agent_client_t *client, struct agent_server_t *as)
{
struct agent_server_t *ser;
  as->bind = as->port;
  ser = find_tunnel_server(as->bind);
  if(!ser) {
    as->type = 309;
    as->tunnel = 0;
    as->hostin[0]='\0';
    as->hostout[0]='\0';
    as->from[0]='\0';
    as->client = NULL;
    as->text = "Reverse Tunnel";
    as->logging = client->logging;
    as->single = 0;
	as->timeout = 0;
    check_agent_local(as);
    ser = new_agent_server(as);
    if(!ser) return -1;
  }
  if(ser->resock != -1) closesocket(ser->resock);
  ser->resock = client->sockin;
  ser->idle = 0;
  client->sockin = -1;
  ser->client = client;
  return 0;
}

static char *cause2str(int cause)
{
	switch(cause) {
	  case 10 : return "client socket shutdown";
	  case 11 : return "client socket error";
	  case 12 : return "client content error";
	  case 13 : return "forward address unreachable";
	  case 14 : return "remote tunnel accepted";
	  case 20 : return "server socket shutdown";
	  case 21 : return "server socket error";
	  case 30 : return "socket keepalive timeout";
	  case 31 : return "queue wait timeout";
    }
	return "unknown";
}

static void *client_routine(void *arg)
{
struct agent_client_t *client;
struct agent_server_t *server, *s;
struct pollfd pfd[2];
int ret, r1, r2, r3, cause=0;
char buff[1024], user[64+1], *p;
char buf1[16384+1], buf2[1024+1];
struct frame_t ln1, ln2;
struct agent_server_t as, tun;

  client = (struct agent_client_t *)arg;
  if(client_wait_turn(client) < 0) { cause=31; goto l_failed; }

  server = client->server;
  ret = open_client_connection(client, server);

  client->welcome = client->self;
//  if(server->holding) server->client = client;
  client->timeout = AGENT_TIMEOUT_MIN;

  output(11, "\n%s#%d : Agent thread forked for %s : %d ==> %s : %d", AppName, client->tid, client->peer, client->bind, client->peerout, client->port);
  pfd[0].fd = client->sockin;
  pfd[0].events = POLLIN;
  pfd[0].revents = 0;
  pfd[1].fd = client->sockout;
  pfd[1].events = POLLIN;
  pfd[1].revents = 0;
  initline(&ln1, buf1, 16384);
  initline(&ln2, buf2, 1024);
  *user = '\0';
  send_ftp_welcome(client);
  send_telnet_prompt(client);
  while(client->running) {
    client->status = 1;
    ret = poll(pfd, client->admin ? 1 : 2, 1000);
	if(ret<0) if(errno == EINTR) continue;
	if(ret<0) { cause=31; break; }
	if(!ret) { client->idle++; client_flush_log(client); client->logind = 0; }
	if(!ret && client->admin==1) client->admin = 0;
	if(!ret) send_ftp_welcome(client);
	if(!ret) send_telnet_prompt(client);
	if(!ret) if(client->idle < client->timeout) continue;
	if(!ret) { cause=30; break; }

l_send10:
    if(pfd[0].revents&POLL_ERROR) { cause=11; break; }
	if(pfd[0].revents&POLLIN) {
	  client->status = 2;
	  ret = recv(client->sockin, buff, 1024, 0);
	  if(!ret) { cause=10; break; }
	  if(ret<0) if(errno==EINTR) ret = 0;
	  if(ret<0) { cause=11; break; }
	  client_write_log(client, 1, buff, ret);
	  client->idle = 0;
	  client->timeout = AGENT_TIMEOUT_MAX;
	  client->sendsize += ret;
	  client->ssize += ret;

l_send16:
	  if(client->admin) {
	    r1 = addline(&ln1, buff, ret);
		if(!r1) continue;
		if(r1<0) goto l_send15;
		ret = 0;
		p = ln1.line + r1;
		if(!ln1.method) {
		  r2 = check_http_request(ln1.line, p, &ln1);
		  if(!r2) goto l_send15;
		  if(!client->type) client->type = 5;
		}
		while(r1) {
		  p = ln1.line + r1;
		  check_http_hostname(ln1.line, p, &ln1);
		  r2 = check_http_head_over(ln1.line);
		  if(r2) break;
		  skipline(&ln1, r1);
		  r1 = addline(&ln1, buff, 0);
		  if(r1<0) goto l_send15;
		}
		if(!r1) continue;

		r2 = check_sock_request(client, &ln1);
		if(r2) {
		  client->type = 6;
		  r2 = handle_sock_request(client, &ln1, &as);
		  if(r2 != 1) { cause=20; break; }
		  strcpy(client->peerout, as.peer);
		  client->port = as.port;
		  client->tunnel = as.tunnel;
		  r2 = open_client_connection(client, &as);
		  if(r2<0) { cause=13; break; }
		  pfd[1].fd = client->sockout;
		  pfd[1].revents = 0;
		}
		client->admin = 0;
	  }

l_send15:
      send_ftp_welcome(client);
      send_telnet_prompt(client);
      if(client->sockout==-1 && client->type%100 == 9) {
	    if(addraw(&ln1, buff, ret)<0) { cause=12; break; }
		ret = 0; 
		r1 = check_tunnel_request(ln1.buff, ln1.size, &as);
		if(!r1) continue;
		if(r1 < 0) { cause=12; break; }
		eatraw(&ln1, r1);
        if(as.type == 309) {
          handle_radius_request(client, &as);
          cause=14; break;
        }
	    r2 = open_tunnel_connection(client, &as, client->bind);
		if(r2 < 0) { cause=13; break; }
		pfd[1].fd = client->sockout;
		pfd[1].revents = 0;
		if(!ln1.size) continue;
		goto l_send16;
	  }

      if(client->sockout == -1 && client->self && (client->type==5 || client->type==6)) {
		r2 = open_http_connection(client, &ln1);
		if(r2<0) { cause=12; break; }
		pfd[1].fd = client->sockout;
		pfd[1].revents = 0;
	  }
	  if(client->sockout == -1 && client->self && (client->type==0 || client->type==8)) {
	    if(addraw(&ln1, buff, ret)<0) { cause=12; break; }
		ret = 0;
	    r1 = check_raw_request(&ln1, &as);
		if(!r1) continue;
		if(r1 < 0) { cause=12; break; }
		client->type = 8;
		eatraw(&ln1, 12);
		r2 = open_raw_connection(client, &as);
		if(r2<0) { cause=13; break; }
		pfd[1].fd = client->sockout;
		pfd[1].revents = 0;
	  }
	  if(client->sockout == -1 && client->self && client->type==101) {
	    if(addraw(&ln1, buff, ret)<0) { cause=12; break; }
		ret = 0;
		r1 = check_telnet_prompt(client, &ln1, ret);
		if(!r1) continue;
		if(r1 < 0) { cause=12; break; }
		eatraw(&ln1, r1);
		if(!ln1.host) continue;
		strcpy(as.peer, ln1.host);
		as.port = ln1.port ? atoi(ln1.port) : 23;
		r2 = open_remote_connection(client, &as, 0);
		if(r2<0) { cause=13; break; }
		pfd[1].fd = client->sockout;
		pfd[1].revents = 0;
		client->self = 0;
	  }
	  if(client->sockout == -1 && client->self == 0) { cause=21; break; }
	  if(client->type != 2) goto l_send12;

l_send14:
	  r1 = addline(&ln1, buff, ret);
	  if(!r1) goto l_send20;
	  if(r1<0) goto l_send12;

	  r2 = check_ftp_proxy(ln1.buff, &ln1, buff);
	  if(client->self && r2==1) {
		eatline(&ln1, r1); ret = 0;
		strcpy(as.peer, ln1.host);
		as.port = ln1.port ? atoi(ln1.port) : 21;
	    r3 = open_ftp_connection(client, &as);
		if(!r3) { 
		  pfd[1].fd = client->sockout; 
		  pfd[1].revents = 0;
		  initline(&ln2, buf2, 1024);
		  client->self = 0; 
		  client->welcome = 0;
		}
		if(!r3 && ln1.user) {
		  strcpy(user, ln1.user);
		  r3 = sprintf(buff, "USER %s\r\n", user);
		  client_write_log(client, 2, buff, r3);
		  client->welcome = 2;
	      if(socksend(client->sockout, buff, r3)<0) { cause=21; break; }
		}
		goto l_send14;
	  }

	  if(client->self) {
		eatline(&ln1, r1); ret = 0;
		if(r2==2 || r2==3) strcpy(user, ln1.user);
		if(r2==2) r3 = sprintf(buff, "331 Password required for %s.\r\n", user);
		else if(r2==3 || r2==4) r3 = sprintf(buff, "230 User %s logged in.\r\n", user);
		else if(r2==5) r3 = sprintf(buff, "221 Goodbye.\r\n");
		else r3 = sprintf(buff, "502 Command not implemented.\r\n");
		client_write_log(client, 4, buff, r3);
		if(socksend(client->sockin, buff, r3)<0) { cause=11; break; }
		goto l_send14;
	  }

	  r2 = check_ftp_active(ln1.buff, &as);
	  if(r2<0) goto l_send12;
      if(r2==1) {
	    as.type = 401;
		as.self = 0;
	    as.bind = server->bind;
	    strcpy(as.from, client->peerout);
	    strcpy(as.hostin, client->hostout);
	    strcpy(as.hostout, client->hostin);
	    as.client = client;
		as.tunnel = 0;
		as.text = "FTP Active";
		as.logging = server->logging;
		as.single = 0;
		as.timeout = AGENT_TIMEOUT_MIN;
	    s = try_agent_server(&as);
	    eatline(&ln1, r1);
	    p = buff + sprintf(buff, "PORT ");
	    p += encode_ftp_address(p, client->hostout, s ? s->bind : 0);
	    p += sprintf(p, "\r\n");
		client_write_log(client, 2, buff, p-buff);
	    if(socksend(client->sockout, buff, p-buff)<0) { cause=21; break; }
	    ret = 0; goto l_send14;
	  }


l_send13:
	  client->status = 3;
	  client_write_log(client, 2, ln1.buff, r1);
      if(socksend(client->sockout, ln1.buff, r1)<0) { cause=21; break; }
	  eatline(&ln1, r1);
	  ret = 0; goto l_send14;

l_send12:
	  client->status = 3;
	  if(client->sockout == -1) { cause=21; break; }
	  client_write_log(client, 2, ln1.buff, ln1.size);
	  if(socksend(client->sockout, ln1.buff, ln1.size)<0) { cause=21; break; }
	  ln1.size = 0;
	  client->status = 5;
	  client_write_log(client, 4, ln2.buff, ln2.size);
	  if(socksend(client->sockin, ln2.buff, ln2.size)<0) { cause=11; break; }
	  ln2.size = 0;
	  if(!client->type) client->type = 1;
	  client->admin = 0;

l_send11:
	  client->status = 3;
	  client_write_log(client, 2, buff, ret);
	  if(socksend(client->sockout, buff, ret)<0) { cause=21; break; }
	}

l_send20:
    if(client->admin) continue;
    if(client->self && client->sockout == -1) continue;
	if(client->sockout == -1) { cause=21; break; }
    if(pfd[1].revents&POLL_ERROR) { cause=21; break; }
	if(pfd[1].revents&POLLIN) {
	  client->status = 4;
	  ret = recv(client->sockout, buff, 1024, 0);
	  if(!ret) { cause=20; break; }
	  if(ret<0) if(errno==EINTR) ret = 0;
	  if(ret<0) { cause=21; break; }
	  client_write_log(client, 3, buff, ret);
	  client->idle = 0;
	  client->timeout = AGENT_TIMEOUT_MAX;
	  client->readsize += ret;
	  client->rsize += ret;

	  if(!client->type && client->readsize==ret && ret>4) {
	    if(!strncmp(buff, "GIOP", 4)) client->type = 7;
	  }

	  if(client->type == 7 && !client->tuning) {
	    r1 = addgiop(&ln2, buff, ret);
		if(r1==-1) { client->type = 0; goto l_send22; }
		if(r1==-2) goto l_send21;
		if(!r1) continue;
		ret = 0;
		r2 = check_giop_reply(&ln2);
		if(!r2) {
		  client_write_log(client, 4, ln2.buff, ln2.size);
		  if(socksend(client->sockin, ln2.buff, ln2.size)<0) { cause=11; break; }
		  eatgiop(&ln2);
		  continue;
		}
		as.type = 7;
		as.self = 0;
		as.bind = client->bind + 1;
		strcpy(as.peer, ln2.host);
		as.port = orb_get_word(ln2.port, ln2.endian);
		as.from[0] = '\0';
		strcpy(as.hostin, client->hostin);
		as.hostout[0] = '\0';
		as.client = client;
		as.tunnel = client->tunnel;
		as.text = "CORBA Service";
		as.logging = server->logging;
		as.single = client->single;
		as.timeout = AGENT_TIMEOUT_MAX;
		s = try_iiop_server(&as);
		r1 = orb_encode_address(buff, &ln2, as.hostin, s ? s->bind : as.port);
	    client_write_log(client, 4, buff, r1);
		if(socksend(client->sockin, buff, r1)<0) { cause=11; break; }
		eatgiop(&ln2);
		continue;
	  }
	  if(client->type && client->type != 2) goto l_send21;

l_send24:
	  r1 = addline(&ln2, buff, ret);
	  if(!r1) continue;
	  if(r1<0) goto l_send22;

	  if(!client->type) {
	    if(check_ftp_welcome(ln2.buff)<=0) goto l_send22;
		client->type = 2;
	  }

	  r2 = skip_ftp_welcome(client, ln2.buff, r1);
	  if(r2) { eatline(&ln2, r1); ret = 0; goto l_send24;	  }

	  r2 = check_ftp_passive(ln2.buff, &as);
	  if(!r2) goto l_send23;
	  if(client->tuning) goto l_send23;
	  if(r2<0) goto l_send22;

	  as.type = 301;
	  as.self = 0;
	  as.bind = server->bind;
	  strcpy(as.from, client->peer);
	  strcpy(as.hostin, client->hostin);
	  strcpy(as.hostout, client->hostout);
	  as.client = client;
	  as.tunnel = client->tunnel;
	  as.text = "FTP Passive";
	  as.logging = server->logging;
	  as.single = 0;
	  as.timeout = AGENT_TIMEOUT_MIN;
	  s = try_agent_server(&as);
	  eatline(&ln2, r1);
	  p = buff + sprintf(buff, "227 Entering Passive Mode (");
	  p += encode_ftp_address(p, client->hostin, s ? s->bind : 0);
	  p += sprintf(p, ")\r\n");
	  client_write_log(client, 4, buff, p-buff);
	  if(socksend(client->sockin, buff, p-buff)<0) { cause=11; break; }
	  ret = 0; goto l_send24;

l_send23:
	  client->status = 5;
	  client_write_log(client, 4, ln2.buff, r1);
      if(socksend(client->sockin, ln2.buff, r1)<0) { cause=11; break; }
	  eatline(&ln2, r1);
	  ret = 0; goto l_send24;

l_send22:
	  client->status = 5;
	  client_write_log(client, 4, ln2.buff, ln2.size);
	  if(socksend(client->sockin, ln2.buff, ln2.size)<0) { cause=11; break; }
	  ln2.size = 0;
	  client_write_log(client, 2, ln1.buff, ln1.size);
	  if(socksend(client->sockout, ln1.buff, ln1.size)<0) { cause=21; break; }
	  ln1.size = 0;
	  if(!client->type) client->type = 1;

l_send21:
	  client->status = 5;
	  client_write_log(client, 4, buff, ret);
	  if(socksend(client->sockin, buff, ret)<0) { cause=11; break; }
	}
  }

  if(client->type==2) end_ftp_client(client);
  client->status = 6;
  if(client->sockin>=0) closesocket(client->sockin);
  if(client->sockout>=0) closesocket(client->sockout);
  client->running = 0;
  output(11, "\n%s#%d : Agent thread exited for %s : %d ==> %s : %d due to %s", AppName, client->tid, client->peer, client->bind, client->peerout, client->port, cause2str(cause));
  if(server->holding) end_agent_server(server);
  if(client->log) fclose(client->log);
  client->tid = 0;
  return NULL;

l_failed:
  if(client->sockin>=0) closesocket(client->sockin); 
  client->running = 0;
  client->tid = 0;
  return NULL; 
}

static void handler(FILE *fp, char *device, int cmd, char *para)
{
int i;
char s1[24], s2[24], s3[24];
struct agent_client_t *client;
  if(cmd==1) {
    i = atoi(para) - 1;
	if(i<0 || i>=numclient) return;
	client = clients + i;
    client->running = 0;
	if(!client->tid) return;
	shutdown(client->sockin, 2);
	shutdown(client->sockout, 2);
	return;
  }
  if(cmd) return;
  _fprintf(fp, "%3s %-19s %-19s %4s %-19s %10s %10s %s\n", "NO", "CLIENT", "SERVER", "TYPE", "CONNECT-TIME", "SEND-SIZE", "RECV-SIZE", "STATUS");
  for(i=0;i<numclient;i++) {
    client = clients + i;
    if(! client->tid) continue;
	sprintf(s1, "%s:%d", client->peer, client->bind);
	sprintf(s2, "%s:%d", client->peerout, client->port);
	sprintt(s3, clients[i].conntv);
	_fprintf(fp, "%3d %-19s %-19s %4s %19s %10.d %10.d ", i+1, s1, s2, type2str(client->type), s3, client->sendsize, client->readsize);
	switch(clients[i].status) {
	  case 0 : _fprintf(fp, "Initializing\n");break;
	  case 1 : _fprintf(fp, "Idle = %ds\n", client->idle);break;
	  case 2 : _fprintf(fp, "Reading from %s:%d\n", client->peer, client->bind);break;
	  case 3 : _fprintf(fp, "Sending to %s:%d\n", client->peerout, client->port);break;
	  case 4 : _fprintf(fp, "Reading from %s:%d\n", client->peerout, client->port);break;
	  case 5 : _fprintf(fp, "Sending to %s:%d\n", client->peer, client->bind);break;
	  case 6 : _fprintf(fp, "Exiting\n"); break;
	  case 7 : _fprintf(fp, "Waiting\n"); break;
	  default : _fprintf(fp, "Unknown(%d)\n", client->status);
	}
  }
}

static int radius_check_server(struct agent_server_t *ser, int pollflag)
{
int ret, sockfd;
char s[32];
struct agent_server_t as;
  if(ser->tuning != 3 && ser->tuning != 4) return 0;
  if(ser->tuning == 3 && !pollflag) return 0;
  if(ser->resock != -1) {
    if(ser->idle<60) return 1;
    as.type = 10;
    strcpy(as.peer, ser->peer);
    as.port = ser->bind;
    ret = send_tunnel_request(NULL, ser->resock, &as);
    if(ret>0) { ser->idle=0; return 1; }
    closesocket(ser->resock);
    ser->resock = -1;
  }
  if(ser->tuning != 4) return -1;
  sprintf(s, "%d", ser->port);
  ret = cliConnect(AF_INET, ser->peer, s, &sockfd);
  if(ret<0) return -1;
  ser->resock = sockfd;
  as.type = 309;
  PrintHostAddress(sockfd, as.peer);
  as.port = ser->bind;
  send_tunnel_request(NULL, sockfd, &as);
  ser->idle = 0;
  return 1;
}

static int radius_poll_server(struct agent_server_t *ser, int pollflag)
{
char buff[256+1];
int ret, head;
struct agent_server_t as;
  if(ser->tuning != 3 && ser->tuning != 4) return 0;
  if(ser->tuning == 3 && !pollflag) return 0;
  if(ser->resock < 0) return -1;
  ret = recv(ser->resock, buff, sizeof(struct tunnel_head_t), MSG_PEEK);
  if(ret>0) ser->idle = 0;
  head = check_tunnel_request(buff, ret, &as);
  if(head > 0) if(as.type != 10) head = 0;
  if(head > 0) ret = recv(ser->resock, buff, head, 0);
  if(ret<0) if(errno == EINTR) return -1;
  if(ret>0) return head>0 ? -1 : 1;
  closesocket(ser->resock);
  ser->resock = -1;
  return -1;
}

int main(int argc, char *argv[])
{
FILE *fp;
char s[1024+1];
char *p, *q;
struct agent_server_t as;
struct agent_server_t *server, *s1;
struct agent_client_t *client;
int i, j, ret, sockfd;
struct rlimit rl;
pthread_attr_t pthattr;
struct pollfd pfd[MAXSERVERS];
int pollflag;

  RunMode = 1;
  appVersion = 0x03180420;
  i = RunApplication(argc, argv, NULL);
  if(i == argc) config = "socks.conf"; else config = argv[i++];


  if(StartApplication() < 0) return -1;

  getrlimit(RLIMIT_NOFILE, &rl);
  rl.rlim_cur = 2048;
  setrlimit(RLIMIT_NOFILE, &rl);

  output(11, "\n%s : Reading config file %s...", AppName, config);
  fp = fopen(config, "r");
  numserver = 0;
  if(fp) while(fgets(s, 1024, fp)) {
    if(*s=='#') continue;
	p = strchr(s, '\n');
	if(p) if(p>s) if(p[-1]=='\r') p--;
	if(p) *p = '\0';
	p = strchr(s, '=');
	if(!p) continue;
	*p++='\0';
	as.type = 0;
	as.bind = strtol(s, &q, 10);
    if(as.bind<0 || as.bind>65535) continue;	
	if(*q=='@') strcpy(as.hostin, q+1); else as.hostin[0] = '\0';
	q = strstr(p, "://");
	if(q) {
	  *q = '\0';
	  as.type = str2type(p);
	  p = q + 3;
	}
	if(as.type != 6 && as.type != 10 && as.bind <= 0) continue;
	if(as.type == 10) as.bind = -1;
	if(as.type == 6 && as.bind <= 0) as.bind = -1;
	for(q=p;*q && *q!=':' && *q!='@' && *q!=';';q++);
	if(q==p) continue;
	i = q - p;
	strncpy(as.peer, p, i);
	as.peer[i] = '\0';
	as.port = *q==':' ? strtol(q+1, &q, 10) : as.bind;
	if(as.port<=0 || as.port>65535) continue;
	if(*q==':') {
	  as.tunnel = strtol(q+1, &q, 10);
	  if(as.tunnel<0 || as.tunnel>65535) continue;
      if(as.type==9) as.tunnel=0;
	}
	else as.tunnel = 0;
	if(as.type==10) if(as.tunnel<1 || as.tunnel>9) continue;
	if(*q=='@') {
	  q++;
	  for(p=q;*q && *q!=';';q++);
	  i = q-p;
	  strncpy(as.hostout, p, i); 
	  as.hostout[i] = '\0';
	}
	else as.hostout[0] = '\0';
	if(*q==';' && (q[1]==';' || q[1]=='\0')) { as.single = 1; q++; } else as.single = 0;
	if(*q==';') as.text = q+1; else as.text = nullstr;
	as.sockfd = -1;
	as.from[0] = '\0';
	as.client = NULL;
	check_agent_local(&as);
	as.logging = 0;
	as.timeout = 0;
	server = new_agent_server(&as);
	if(!server) continue;
  }
  if(fp) fclose(fp);
  if(!fp) {
    as.type = 6;
	as.bind = 2300;
	as.hostin[0] = '\0';
	strcpy(as.peer, "127.0.0.1");
	as.port = 2300;
	as.tunnel = 0;
	as.hostout[0] = '\0';
	as.sockfd = -1;
	as.from[0] = '\0';
	as.client = NULL;
	as.text = "Socks Admin";
	check_agent_local(&as);
	as.logging = 0;
	as.single = 0;
	as.timeout = 0;
	server = new_agent_server(&as);
	if(!server) return 0;

	as.type = 9;
	as.bind = 2400;
	as.hostin[0] = '\0';
	strcpy(as.peer, "127.0.0.1");
	as.port = 2400;
	as.tunnel = 0;
	as.hostout[0] = '\0';
	as.sockfd = -1;
	as.from[0] = '\0';
	as.client = NULL;
	as.text = "Socks Tunnel";
	check_agent_local(&as);
	as.logging = 0;
	as.single = 0;
	as.timeout = 0;
	server = new_agent_server(&as);

  }

  SetAppCommandHandler5(handler);
  pthread_attr_init(&pthattr);
  pthread_attr_setdetachstate(&pthattr, PTHREAD_CREATE_DETACHED);
  pthread_attr_setscope(&pthattr, PTHREAD_SCOPE_SYSTEM);

  for(pollflag=0;appRunning;pollflag=1-pollflag) {
    for(i=0, s1=NULL;i<numserver;i++) {
	  server = servers + i;
	  radius_check_server(server, pollflag);
	  if(server->timeout && server->idle > server->timeout) {
	    for(j=0;j<numclient;j++) if(clients[j].tid && clients[j].server == server) break;
		if(j==numclient) end_agent_server(server);
	  }
	  pfd[i].fd = server->tuning==4 || (server->tuning==3 && pollflag) ? server->resock : server->sockfd;
	  pfd[i].events = POLLIN;
	  server->idle++;
	}
    ret = poll(pfd, numserver, 1000);
	if(ret<=0) continue;
	for(i=0;i<numserver;i++) if(pfd[i].revents&POLLIN) {
	  server = servers + i;
      if(radius_poll_server(server, pollflag)<0) continue;
	  if(server->tuning == 3 && pollflag) continue;
      sockfd = server->tuning==4 ? server->resock : accept(server->sockfd, NULL, 0);
	  if(sockfd < 0) continue;
	  for(j=0;j<numclient;j++) if(! clients[j].tid) break;
      if(j==MAXCLIENTS && server->tuning!=4) closesocket(sockfd);
	  if(j==MAXCLIENTS) continue;
	  if(j==numclient) numclient++;
	  client = clients + j;
	  client->tid = 0;
	  client->conntv = time(NULL);
	  PrintPeerAddress(sockfd, client->peer);
	  PrintHostAddress(sockfd, client->hostin);
	  output(11, "\n%s$%d : Accepted connection from %s ==> %s:%d = %d", AppName, server - servers, client->peer, client->hostin, server->bind, sockfd);
	  for(j=ret=0;j<numclient;j++) if(clients[j].tid && clients[j].server == server && clients[j].conntv >= client->conntv) ret++;
      if(ret >= AGENT_FLOW_CONTROL) { 
		    output(101, " ... abandoned for %d connections in process.", ret);
		    closesocket(sockfd);
		    continue;
	  }
	  client->sockin = sockfd;
	  client->admin = 1;
      if(server->tuning==4) server->resock = -1;

      trylock();
      for(j=0, s1=servers;j<numserver;j++, s1++) {
	    if(s1->holding==1) if(!strcmp(s1->from, client->peer)) server = s1;
		if(s1->self) if(s1->type==5 || s1->type==6) client->admin = 0;
	  }
	  locked = 0;
	  if(server->holding == 1) {
	    if(strcmp(client->peer, server->from)) { closesocket(sockfd); continue; }
		server->holding = 2;
	  }
	  if(server->self) if(server->type==5 || server->type==6) client->admin = 2;
	  if(server->hostin[0]) strcpy(client->hostin, server->hostin);

      server->idle = 0;
	  client->server = server;
	  client->self = server->self;
	  client->type = server->type;
	  client->bind = server->bind;
	  client->sendsize = 0;
	  client->readsize = 0;
	  client->ssize = 0;
	  client->rsize = 0;
	  client->status = 0;
	  client->log = NULL;
	  client->logging = server->logging;
	  client->logind = 0;
	  client->sockout = -1;
	  strcpy(client->hostout, server->hostout);
	  strcpy(client->peerout, server->tuning==4 ? "127.0.0.1" : server->peer);
	  client->port = server->tuning==4 ? server->bind : server->port;
	  client->dest = 0;
	  client->peerto[0] = '\0';
	  client->tunnel = server->tunnel;
	  client->tuning = server->tuning;
	  client->single = server->single;
	  client->running = 1;
	  pthread_create(&(client->tid), &pthattr, client_routine, client);
	}
  }
  for(i=0;i<numclient;i++) {
    client = clients + i;
    client->running = 0;
	if(! client->tid) continue;
	shutdown(client->sockin, 2);
	if(client->sockout != -1) shutdown(client->sockout, 2);
  }
  for(i=0;i<numclient;i++) while(clients[i].tid) poll(NULL, 0, 100);
  for(i=0;i<numserver;i++) if(servers[i].bind) end_agent_server(servers+i);
  pthread_attr_destroy(&pthattr);
  return 0;
}

static int ctoh(char c)
{
  if(c>='0' && c<='9') return c-'0';
  else if(c>='a' && c<='f') return c-'a'+10;
  else return c-'A'+10;
}

static int http_decode(char *from, char *to, char *dst, int method)
{
char *p,c;
  for(p=from;p<to;p++) {
    c=*p;
    if(c=='%') { *dst++=ctoh(p[1])*16+ctoh(p[2]); p+=2; }
    else if(c=='+' && method==1) *dst++=' ';
    else *dst++=c;
  }
  *dst='\0';
  return 0;
}

static char *http_get_value(struct frame_t *h, char *name, char *value)
{
char *p, *p1, *p2;
char s[256+1];
  *value='\0';
  if(h->arg==NULL) return NULL;
  for(p1=h->arg;p1<h->version-1;p1=p+1) {
    for(p=p1,p2=NULL;p<h->version-1 && *p!='&';p++) if(*p=='=' && !p2) p2=p;
	if(!p2) continue;
	if(p2) http_decode(p1, p2, s, h->method); else *s='\0';
	if(strcasecmp(s, name)) continue;
	p1 = p2 ? p2+1 : p1;
	http_decode(p1, p, value, h->method);
	return *value ? p1 : NULL;
  }
  return NULL;
}

static int http_get_value_list(struct frame_t *h, char *name, char *value, char *values[])
{
char *p, *p1, *p2;
char s[256+1];
int count;
  *value='\0';
  *values = NULL;
  if(h->arg==NULL) return 0;
  for(p1=h->arg,count=0;p1<h->version-1;p1=p+1) {
    for(p=p1,p2=NULL;p<h->version-1 && *p!='&';p++) if(*p=='=' && !p2) p2=p;
	if(!p2) continue;
	if(p2) http_decode(p1, p2, s, h->method); else *s='\0';
	if(strcasecmp(s, name)) continue;
	http_decode(p2 ? p2+1 : p1, p, value, h->method);
	if(*value=='\0') continue;
	values[count++] = value;
	value += strlen(value)+1;
  }
  values[count] = NULL;
  return count;
}

static int http_get_int(struct frame_t *h, char *name, int value)
{
char s[256+1];
  if(!http_get_value(h, name, s)) return value;
  if(*s=='\0') return value;
  return atoi(s);
}

static int cb_sort_int_descending(int *a, int *b)
{
  return (*b) - (*a);
}

static int http_get_int_list(struct frame_t *h, char *name, int values[])
{
char *p, *p1, *p2;
char s[256+1], value[512+1];
int count;
  *values = 0;
  if(h->arg==NULL) return 0;
  for(p1=h->arg,count=0;p1<h->version-1;p1=p+1) {
    for(p=p1,p2=NULL;p<h->version-1 && *p!='&';p++) if(*p=='=' && !p2) p2=p;
	if(!p2) continue;
	if(p2) http_decode(p1, p2, s, h->method); else *s='\0';
	if(strcasecmp(s, name)) continue;
	http_decode(p2 ? p2+1 : p1, p, value, h->method);
	if(*value=='\0') continue;
	values[count++] = atoi(value);
  }
  values[count] = 0;
  qsort(values, count, sizeof(int), cb_sort_int_descending);
  return count;
}

static int handle_sock_command(struct agent_client_t *client, struct frame_t *h, int cmd)
{
struct agent_client_t *cli;
struct agent_server_t *ser;
struct agent_server_t as;
int list[1024+1],i,n,count,index;
FILE *fp;
char s[1024+1], *p;
    switch(cmd) {
	  case 1 : 
	    index = http_get_int(h, "index", -1);
	    if(index<0 || index>=numserver) return -1;
		ser = servers + index;
		if(!ser->bind) return -1;
		if(ser->client) return -1;
		as.type = http_get_int(h, "type", 0);
		http_get_value(h, "peer", as.peer);
		if(as.peer[0]=='\0') return -1;
		as.port = http_get_int(h, "port", 0);
		if(as.port<=0 || as.port>65535) return -1;
		as.tunnel = http_get_int(h, "tunnel", 0);
		if(as.tunnel<0 || as.tunnel>65535) return -1;
		if(as.type == 9) as.tunnel = 0;
		strcpy(ser->peer, as.peer);
		ser->port = as.port;
		ser->tunnel = as.tunnel;
		http_get_value(h, "hostout", ser->hostout);
		ser->type = as.type;
		check_agent_local(ser);
		http_get_value(h, "text", s);
		set_agent_text(ser, s);
		ser->logging = http_get_int(h, "log", 0);
		ser->single = http_get_int(h, "single", 0);
		break;

	  case 2 :
        count = http_get_int_list(h, "index", list);
		for(i=0;i<count;i++) {
		  index = list[i];
	      if(index<0 || index>=numserver) continue;
		  ser = servers + index;
		  if(!ser->bind) continue;
		  if(ser==client->server) continue;
		  end_agent_server(ser);
		}
		break;

	  case 3 :
		as.bind = http_get_int(h, "bind", 0);
		if(as.bind<0 || as.bind>65535) return -1;
		as.type = http_get_int(h, "type", 0);
		if(as.type != 6 && as.bind <= 0) return -1;
		if(as.type == 6 && as.bind <= 0) as.bind = -1;
		http_get_value(h, "peer", as.peer);
		if(as.peer[0]=='\0') return -1;
		as.port = http_get_int(h, "port", as.bind);
		if(as.port<=0 || as.port>65535) return -1;
		as.tunnel = http_get_int(h, "tunnel", 0);
		if(as.tunnel<0 || as.tunnel>65535) return -1;
		if(as.type == 9) as.tunnel = 0;
		http_get_value(h, "hostin", as.hostin);
		http_get_value(h, "hostout", as.hostout);
	    as.from[0] = '\0';
	    as.client = NULL;
		as.sockfd = -1;
		check_agent_local(&as);
		http_get_value(h, "text", s);
		as.text = s;
		as.logging = http_get_int(h, "log", 0);
		as.single = http_get_int(h, "single", 0);
		as.timeout = 0;
	    ser = new_agent_server(&as);
		if(!ser) return -1;
	    break;

	  case 11:
        count = http_get_int_list(h, "index", list);
		for(i=0;i<count;i++) {
		  index = list[i];
		  cli = clients + index;
		  if(!cli->tid) continue;
		  if(cli == client) continue;
		  cli->running = 0;
		  shutdown(cli->sockin,2);
		  if(cli->sockout!=-1) shutdown(cli->sockout,2);
		  for(n=20;cli->tid && n>0;n--) poll(NULL, 0, 50);
		}
		return 1;
		break;

	  default:
	    return -1;

	}
	fp = fopen(config, "w");
	if(!fp) return 0;
	for(index=0;index<numserver;index++) {
	  ser = servers + index;
	  if(!ser->bind) continue;
	  if(ser->client) continue;
	  p = s;
	  p += sprintf(p, "%d", ser->bind<0 ? 0 : ser->bind);
	  if(ser->hostin[0]) p+=sprintf(p, "@%s", ser->hostin);
	  *p++ = '=';
	  if(ser->type) p += sprintf(p, "%s://", type2str(ser->type));
	  p += sprintf(p, "%s:%d", ser->peer, ser->port);
	  if(ser->tunnel && ser->tunnel != ser->bind) p+=sprintf(p, ":%d", ser->tunnel);
	  if(ser->hostout[0]) p+=sprintf(p, "@%s", ser->hostout);
	  if(ser->single) *p++=';';
	  if(ser->text[0]) p += sprintf(p, ";%s", ser->text);
	  *p++ = '\n';
	  fwrite(s, 1, p-s, fp);
	}
	fclose(fp);
	return 1;
}

static char *option2str(int v1, int v2) { return v1==v2 ? " selected" : nullstr; }
static char *value2str(char *s, char *v) { if(*v) sprintf(s, " value=\"%s\"", v); else *s='\0'; return s; }

static void str2html(char *dst, char *src)
{
char* amp[] = { "&amp", ">gt", "<lt" , "\"quot" , NULL };
char *p, *s;
int i;
  for(p=src;*p;p++) {
    for(i=0;(s=amp[i]);i++) if(*p==*s) break;
	if(s) dst += sprintf(dst, "&%s;", s+1);
	else *dst++ = *p;
  }
  *dst = '\0';
}

static int expect(char *s1, int len, char *s2)
{
int n = strlen(s2);
  if(len>0) if(s1[len-1]=='\n') len--;
  if(len>0) if(s1[len-1]==' ') len--;
  if(len < n) return 0;
  return strncmp(s1+len-n, s2, n)==0;
}

static int expect_prompt(char *s, int len, int super)
{
char ch;
  if(len>0) if(s[len-1]=='\n') len--;
  if(len>0) if(s[len-1]==' ') len--;
  if(len < 1) return 0;
  ch = s[len-1];
  return ch=='$' || ch=='>' || ch=='%' || (super && ch=='#');
}


static int handle_release_command(struct agent_client_t *client, struct frame_t *h, char *submit)
{
char host[32+1], user[16+1], pass[16+1], run[32+1];
char local[256+1], remote[256+1], path[256+1];
char s[256+1], line[256+1], *p, *s1, *name;
int os=0, zip=0, action, i, len, ind, idle, ret;
FILE *fp, *xp;
int pid, pin[2], pout[2];
struct pollfd pfd;
  if(!strcmp(submit, "Upload")) action = 1;
  else if(!strcmp(submit, "Release")) action = 7;
  else if(!strcmp(submit, "Restart")) action = 4;
  else return -1;

  http_get_value(h, "os", s);
  if(!strcmp(s, "linux")) os = 1;
  else if(!strcmp(s, "solaris")) os = 2;
  http_get_value(h, "host", host);
  http_get_value(h, "user", user);
  http_get_value(h, "pass", pass);
  http_get_value(h, "local", local);
  http_get_value(h, "remote", remote);
  http_get_value(h, "path", path);
  http_get_value(h, "run", run);

  if(*host=='\0') return -1;
  if(*user=='\0') return -1;
  if(*pass=='\0') return -1;
  if(*local=='\0' && (action&1)) return -1;
  if(*remote=='\0' && (action&1)) return -1;
  if(*path=='\0' && (action&6)) return -1;
  if(!strcmp(remote, path) && (action&2)) return -1;
  if(!strcmp(run, "socks")) *run = '\0';

  p = strrchr(local, '/');
  name = p ? p+1 : local;
  p = strrchr(name, '.');
  if(p) {
    if(!strcmp(p, ".tar")) zip = 2;
	else if(!strcmp(p, ".gz")) zip = 1;
	else if(!strcmp(p, ".tgz")) zip = 3;
  }

  if(action&1) {
  sock_printf(client->sockin, "\n======Uploading %s : %s to %s@%s : %s ...\n", client->hostin, local, user, host, remote);
  p = strrchr(local, '.');
  s1 = "/tmp/socks.rel.ftp";
  fp = fopen(s1, "w");
  if(!fp) return -1;
  fprintf(fp, "open %s\n", host);
  fprintf(fp, "user %s %s\n", user, pass);
  fprintf(fp, "cd %s\n", remote);
  if(name > local) { name[-1]='\0'; fprintf(fp, "lcd %s\n", local); }
  fprintf(fp, "bin\n");
#ifdef sun
  fprintf(fp, "passive\n");
#endif
  fprintf(fp, "put %s\n", name);
  fprintf(fp, "close\n");
  fprintf(fp, "bye\n");
  fclose(fp);
  sprintf(s, "ftp -n < %s 2>&1", s1);
  xp = popen(s, "r");
  if(!xp) return -1;
  while(fgets(line, 256, xp)) {
    sock_printf(client->sockin, "%s", line);
  }
  pclose(xp);
  sock_printf(client->sockin, "\n======Uploading finished. Please check the above information to assure.");
  }

  if(action&6) {
  sock_printf(client->sockin, "\n======Restarting socks at %s@%s : %s ...\n", user, host, path);
  if(pipe(pin)<0) return -1;
  if(pipe(pout)<0) { close(pin[0]); close(pin[1]); return -1; }
  pid = fork();
  if(!pid) {
    dup2(pin[0], 0);
	dup2(pout[1], 1);
	dup2(pout[1], 2);
    for(i=3;i<FOPEN_MAX;i++) close(i);
	sprintf(s, "telnet %s", host);
	execl("/bin/sh", "sh", "-c", s, NULL);
	exit(0);
  }
  pfd.fd = pout[0];
  pfd.events = POLLIN;
  for(ind=idle=len=0;idle<60;) {
    if(pid>0) if(kill(pid, 0)) pid=0;
	if(!pid) break;
    ret = poll(&pfd, 1, 1000);
	if(ret<0) continue;
	if(!ret) idle++;
	if(ret) {
	  if(len>128) { memcpy(line, line+len-128, 128); len=128; }
	  ret = read(pout[0], line+len, 128);
	  if(ret<=0) break;
	  socksend(client->sockin, line+len, ret);
	  len += ret; idle=0; 
	  continue;
	}
	line[len] = '\0';
	if(ind == 0 && idle > 10) break;
	if(ind == 1 && idle > 10) break;
	if(ind == 2 && idle > 10) break;
	if(ind == 4 && idle > 1) break;
	if(idle > 60) break;

	if(expect(line, len, "ogin:") && ind<2) {
	  ret = sprintf(s, "%s\r", user);
	  write(pin[1], s, ret);
	  ind = 1; len = 0;
	}
	else if(expect(line, len, "assword:") && ind==1) {
	  ret = sprintf(s, "%s\r", pass);
	  write(pin[1], s, ret);
	  ind = 2; len = 0;
	}
	else if(expect_prompt(line, len, 0) && ind==2) {
	  ret = 0;
	  if(action&2) {
	    ret += sprintf(s+ret, "cd %s", remote);
	    if(zip==1) ret += sprintf(s+ret, ";gzip -d %s", name);
	    else if(zip==2) ret += sprintf(s+ret, ";tar xvf %s", name);
	    else if(zip==3 && os==1) ret += sprintf(s+ret, ";tar zxvf %s", name);
	    else if(zip==3) ret += sprintf(s+ret, ";gzip -cd %s | tar xvf -", name);
	    ret += sprintf(s+ret, ";chmod +x socks; mkdir -p %s; mv -f socks %s", path, path);
	  }
	  if(ret) s[ret++]=';';
	  if(*run) ret += sprintf(s+ret, "cd %s; ./socks -n%s -x; ./socks -n%s\r", path, run, run);
	  else ret += sprintf(s+ret, "cd %s; ./socks -x; ./socks\r", path);
      write(pin[1], s, ret);
	  ind = 3; len = 0;
	}
	else if(ind == 3 && idle>1) {
	  ret = sprintf(s, "exit\r");
	  write(pin[1], s, ret);
	  ind = 4; len = 0;
	}
  }
  if(pid>0) kill(pid, 9);
  close(pin[0]);
  close(pin[1]);
  close(pout[0]);
  close(pout[1]);

  if(ind < 4) return -1;
  sock_printf(client->sockin, "\n======Restarting finished. Please check the above information to assure.");
  }
  return 0;

}

static int handle_release_request(struct agent_client_t *client, struct frame_t *h, char *submit, char *route)
{
char s[256+1], v[256+1];
int os;
  sock_printf(client->sockin, "<H3 align=center>Socks Program Release Tool [ %s ]</H3>\n", client->hostin);
  getcwd(s, 256);
  sprintf(v, "%x.%02x.%04x", (appVersion>>24)&0xff, (appVersion>>16)&0xff, appVersion&0xffff);
  sock_printf(client->sockin, "<P align=center><B>[ %s %s %s ]</B></P>\n", s, AppName, v);
  sock_printf(client->sockin, "<PRE>");
  if(*submit) handle_release_command(client, h, submit);
  sock_printf(client->sockin, "</PRE><FORM method=GET action=\"/socks\">\n");
  sock_printf(client->sockin, "<input type=hidden name=cmd value=100>\n");
  if(*route) sock_printf(client->sockin, "<input type=hidden name=route value=\"%s\">\n", route);
  sock_printf(client->sockin, "<table border=1>\n");
  sock_printf(client->sockin, "<tr><td>OS</td><td>IP</td><td>User</td><td>Password</td><td>Local File</td><td>Upload Path</td><td>Release Path</td><td>Run Name</td></tr>\n");
  sock_printf(client->sockin, "<tr>");
  sock_printf(client->sockin, "<td><select name=os>\n");
  http_get_value(h, "os", v);
  if(*v=='\0') os = 1;
  else if(!strcmp(v, "linux")) os = 1;
  else if(!strcmp(v, "solaris")) os = 2;
  else os = 0;
  sock_printf(client->sockin, "<option value=linux%s>linux</option>\n", option2str(os, 1));
  sock_printf(client->sockin, "<option value=solaris%s>solaris</option>\n", option2str(os, 2));
  sock_printf(client->sockin, "<option value=other%s>other</option>\n", option2str(os, 0));
  sock_printf(client->sockin, "</select></td>\n");
  http_get_value(h, "host", v);
  sock_printf(client->sockin, "<td><input type=text name=host size=16%s></td>", value2str(s, v));
  http_get_value(h, "user", v); if(*v=='\0') strcpy(v, "zc");
  sock_printf(client->sockin, "<td><input type=text name=user size=8%s></td>", value2str(s,v));
  http_get_value(h, "pass", v); if(*v=='\0') strcpy(v, "zcxc123");
  sock_printf(client->sockin, "<td><input type=password name=pass size=10%s></td>", value2str(s, v));
  http_get_value(h, "local", v); 
  sock_printf(client->sockin, "<td><input type=text name=local size=48%s></td>", value2str(s, v));
  http_get_value(h, "remote", v); if(*v=='\0') strcpy(v, "/tmp");
  sock_printf(client->sockin, "<td><input type=text name=remote size=24%s></td>", value2str(s,v));
  http_get_value(h, "path", v); if(*v=='\0') strcpy(v, "/home/zc/.zctask/bin");
  sock_printf(client->sockin, "<td><input type=text name=path size=24%s></td>", value2str(s,v));
  http_get_value(h, "run", v); if(*v=='\0') strcpy(v, "socks");
  sock_printf(client->sockin, "<td><input type=text name=run size=12%s></td>", value2str(s,v));
  sock_printf(client->sockin, "</tr>\n");
  sock_printf(client->sockin, "<tr><td colspan=8>");
  sock_printf(client->sockin, "<input type=submit name=submit value=\"Release\">");
  sock_printf(client->sockin, "<input type=submit name=submit value=\"Upload\">");
  sock_printf(client->sockin, "<input type=submit name=submit value=\"Restart\">");
  sock_printf(client->sockin, "</td></tr>\n");
  sock_printf(client->sockin, "</table><br>\n");
  sock_printf(client->sockin, "</FORM>\n");
  sock_printf(client->sockin, "</BODY>\n</HTML>\n");    
  return 0;
}

static int check_forward_request(char *value, char *route, struct agent_server_t *as)
{
char *s, *p;
int n;
  if(*route=='\0') return 0;
  for(p=route;*p && *p!=';';p++);
  if(*p=='\0') return 0;
  s = p+1;
  for(p=s;*p && *p!=',' && *p!=';' && *p!=':';p++);
  if(p==s || *p!=':') return -1;
  as->type = 6;
  n = p - s;
  strncpy(as->peer, s, n);
  as->peer[n]='\0';
  s=p+1; as->port = strtol(s, &p, 0);
  if(p==s) return 0;
  as->tunnel = *p==':' ? atoi(p+1) : 0;
  as->self = 0;
  for(p=value;*p && *p!='&' && *p!=' ';p++) {
    if(*p==';') { *p++=','; break; }
	if(*p=='%' && p[1]=='3' && (p[2]=='b' || p[2]=='B')) { p[1]='2'; p[2]='c'; p+=3; break; }
  }
  for(s=p;*p && *p!='&' && *p!=' ';p++) {
    if(*p==',') { *p++=';'; break; }
	if(*p=='%' && p[1]=='2' && (p[2]=='c' || p[2]=='C')) { p[1]='3'; p[2]='b'; p+=3; break; }
  }
  return 1;
}

static char *check_route(struct agent_client_t *client, struct frame_t *h, char *route, char *host)
{
char *s, *p;
int n;
  for(s=p=route;*p;p++) if(*p==',' || *p==';') { s=p+1; *p=';'; }
  if(*s && *s!=',' && *s!=';' && *s!=':') {
    for(p=s;*p && *p!=',' && *p!=';' && *p!=':';p++);
	n=p-s; strncpy(host, s, n); host[n]='\0';
  }
  else if(h->host) {
    for(p=h->host;*p && *p!=':' && *p!='/' && *p!='\r' && *p!='\n' && *p!=' ';p++) if(p==h->port) break;
	n=p-h->host; strncpy(host, h->host, n); host[n]='\0';
  }
  else strcpy(host, client->hostin);
  return s;
}

static int handle_sock_request(struct agent_client_t *client, struct frame_t *h, struct agent_server_t *as)
{
char s[256+1], v[256+1], x[256+1];
int i,j,n,cmd,ret,type, quiet;
struct agent_client_t *cli;
struct agent_server_t *ser;
char route[256+1], *p, *me;
char self[256+1], host[64+1];
int list[MAXSERVERS];

  p = http_get_value(h, "route", route);
  ret = check_forward_request(p, route, as);
  if(ret) return ret;
  me = check_route(client, h, route, host);
  
  if(*route) sprintf(self, "/socks?route=%s", route); else strcpy(self, "/socks");
  sock_printf(client->sockin, "HTTP/1.0 200\n");
  sock_printf(client->sockin, "Content-type: text/html\n");
  sock_printf(client->sockin, "\n");

  cmd = http_get_int(h, "cmd", 0);
  if(cmd==-1) { appRunning=0; return 0; }
  quiet = http_get_int(h, "quiet", 0);

  sock_printf(client->sockin, "<HTML>\n<HEAD>\n<TITLE>Socks Proxy [%s] Administration</TITLE>\n<META HTTP-EQUIV=\"pragma\" CONTENT=\"no-cache\">\n</HEAD><BODY>\n", client->hostin);

  http_get_value(h, "submit", s);
  if(cmd==100) return handle_release_request(client, h, s, route);
  ret = *s ? handle_sock_command(client, h, cmd) : 0;
  if(quiet) return 0;

  sock_printf(client->sockin, "<script language=\"javascript\">\n");
  sock_printf(client->sockin, "  function onchoose(value) {\n");
  sock_printf(client->sockin, "    var o1,o2,o3;\n");
  sock_printf(client->sockin, "    o3 = document.getElementById( \"ed_cmd\");\n");
  sock_printf(client->sockin, "    if(o3.value==3) document.getElementById( \"ed_hostin\").disabled = (value!=2 && value!=7 && value!=9);\n");
  sock_printf(client->sockin, "    document.getElementById( \"ed_hostout\").disabled = (value!=2 && value!=9);\n");
  sock_printf(client->sockin, "    o1 = document.getElementById( \"ed_bind\");\n");
  sock_printf(client->sockin, "    o2 = document.getElementById( \"ed_port\");\n");
  sock_printf(client->sockin, "    if(value == 101) { if(o3.value==3) { o1.value = '2000'; o2.value=23; }} \n");
  sock_printf(client->sockin, "    else if(value == 2) { if(o3.value==3) { o1.value = '2100'; o2.value=21; }} \n");
  sock_printf(client->sockin, "    else if(value == 201) { if(o3.value==3) { o1.value = '2200'; o2.value=22; }} \n");
  sock_printf(client->sockin, "    else if(value == 5) { if(o3.value==3) { o1.value = '2800'; o2.value=80; }} \n");
  sock_printf(client->sockin, "    else if(value == 6) { if(o3.value==3) { o1.value = '2300'; o2.value=2300; }} \n");
  sock_printf(client->sockin, "    else if(value == 7) { if(o3.value==3) { o1.value = '2900'; o2.value=2809; }} \n");
  sock_printf(client->sockin, "    else if(value == 8) { if(o3.value==3) { o1.value = '2600'; o2.value=8099; }} \n");
  sock_printf(client->sockin, "    else if(value == 9) { if(o3.value==3) { o1.value = '2400'; o2.value=2400; }} \n");
  sock_printf(client->sockin, "    else if(value == 501) { if(o3.value==3) { o1.value = '2700'; o2.value=9876; }} \n");
  sock_printf(client->sockin, "    else if(value == 601) { if(o3.value==3) { o1.value = '2500'; o2.value=25; }} \n");
  sock_printf(client->sockin, "    else if(value == 701) { if(o3.value==3) { o1.value = '2500'; o2.value=110; }} \n");
  sock_printf(client->sockin, "    else if(value == 801) { if(o3.value==3) { o1.value = '2300'; o2.value=389; }} \n");
  sock_printf(client->sockin, "    else if(value == 901) { if(o3.value==3) { o1.value = '2400'; o2.value=1521; }} \n");
  sock_printf(client->sockin, "    else if(value == 1001) { if(o3.value==3) { o1.value = '2400'; o2.value=2640; }} \n");
  sock_printf(client->sockin, "    else if(value == 1201) { if(o3.value==3) { o1.value = '2500'; o2.value=143; }} \n");
  sock_printf(client->sockin, "    else if(value == 1301) { if(o3.value==3) { o1.value = '2000'; o2.value=5900; }} \n");
  sock_printf(client->sockin, "    else if(value == 1401) { if(o3.value==3) { o1.value = '2000'; o2.value=3389; }} \n");
  sock_printf(client->sockin, "    else if(value == 409) { if(o3.value==3) { o1.value = '2400'; o2.value=2400; }} \n");
  sock_printf(client->sockin, "  }\n");
  sock_printf(client->sockin, "</script>\n");


  sock_printf(client->sockin, "<FORM method=GET action=\"/socks\">\n");
  if(*route) sock_printf(client->sockin, "<input type=hidden name=route value=\"%s\">\n", route);
  sock_printf(client->sockin, "<input type=hidden name=cmd value=2>\n");
  sock_printf(client->sockin, "<table border=2 cellspacing=2 cellpadding=2 style=\"font-size:13px\" frame=\"box\">\n");
  sock_printf(client->sockin, "<tr bgcolor=\"#F1F5FB\" ><td colspan=6 align=center><a href=\"%s\"><B>Socket Listen List</B></a><B>[ %s ]</B><a href=\"%s\">Refresh</a></td>\n", self, client->hostin, self);
  sock_printf(client->sockin, "<td></td>\n");
  getcwd(s, 256);
  sprintf(v, "%x.%02x.%04x", (appVersion>>24)&0xff, (appVersion>>16)&0xff, appVersion&0xffff);
  sock_printf(client->sockin, "<td colspan=6><input type=submit name=submit value=Shutdown> <B>[ %s %s %s ]</B></td>\n", s, AppName, v);
  sock_printf(client->sockin, "<tr bgcolor=\"#F1F5FB\" >");
  sock_printf(client->sockin, "<td>Index</td>");
  sock_printf(client->sockin, "<td>Type</td>");
  sock_printf(client->sockin, "<td>Listen on</td>");
  sock_printf(client->sockin, "<td>Forward to</td>\n");
  sock_printf(client->sockin, "<td>Tunnel</td>\n");
  sock_printf(client->sockin, "<td>Description</td>\n");
  sock_printf(client->sockin, "<td></td>");
  sock_printf(client->sockin, "<td>Index</td>");
  sock_printf(client->sockin, "<td>Type</td>");
  sock_printf(client->sockin, "<td>Listen on</td>");
  sock_printf(client->sockin, "<td>Forward to</td>\n");
  sock_printf(client->sockin, "<td>Tunnel</td>\n");
  sock_printf(client->sockin, "<td>Description</td>\n");
  sock_printf(client->sockin, "</tr>\n");
  for(i=n=0;i<numserver;i++) {
    ser = servers + i;
	if(!ser->bind) continue;
	list[n++] = i;
  }
  for(j=0;j<n;j++) {
    if(j%2==0) i = list[j/2]; else i = list[(j+n)/2];
    ser = servers + i;
	if(j%2==0) sock_printf(client->sockin, "<tr bgcolor=\"#FFFFFF\" >");
	else sock_printf(client->sockin, "<td></td>\n");
	if(ser->logging) sprintf(s, "<B>%d</B>", i); else sprintf(s, "%d", i);
	sock_printf(client->sockin, "<td><input type=checkbox name=index value=%d size=1>%s</td>\n", i, s);
	sock_printf(client->sockin, "<td>%s</td>\n", type2str(ser->type));
	sprintf(s, "%s --&gt; %s:%d", ser->from[0] ? ser->from : "*", ser->hostin[0] ? ser->hostin : "*", ser->bind<0 ? 0 : ser->bind); 
	if(ser->type == 6 && ser->bind == -1) {
	  if(ser->tunnel) sprintf(x, "%s:%d:%d", ser->peer, ser->port, ser->tunnel); else sprintf(x, "%s:%d", ser->peer, ser->port);
	  sprintf(v, "/socks?route=%s;%s", route, x);
	  sock_printf(client->sockin, "<td><a href=\"%s\" target=\"_blank\">%s</a></td>\n", v, s);	  
	}
	else if(ser->type == 6 && ser->self) {
	  if(*route) sprintf(v, "/socks?route=%s", route); else strcpy(v, "/socks");
	  sock_printf(client->sockin, "<td><a href=\"%s\" target=\"_blank\">%s</a></td>\n", v, s);
	}
	else if(ser->type == 6 && strcmp(host, client->hostin)) {
	  if(ser->tunnel) sprintf(x, "%s:%d:%d", ser->peer, ser->port, ser->tunnel); else sprintf(x, "%s:%d", ser->peer, ser->port);
	  sprintf(v, "/socks?route=%s;%s", route, x);
	  sock_printf(client->sockin, "<td><a href=\"%s\" target=\"_blank\">%s</a></td>\n", v, s);
	}
	else if(ser->type == 6 && *route) { 
	  ret = me - route;
	  if(ret>0) { ret--; strncpy(x, route, ret); }
	  x[ret]='\0';
	  sprintf(v, "/socks?route=%s;%s:%d", x, host, ser->bind);
	  sock_printf(client->sockin, "<td><a href=\"%s\" target=\"_blank\">%s</a></td>\n", v, s);
	}
	else if(ser->type == 6) {
	  sprintf(v, "http://%s:%d/socks", host, ser->bind);
	  sock_printf(client->sockin, "<td><a href=\"%s\" target=\"_blank\">%s</a></td>\n", v, s);
	}
	else if(ser->type == 10) {	  
	  sprintf(v, "/socks?route=%s;%s:%d&cmd=21&radius=%d&submit=dial", route, ser->peer, ser->port, ser->tunnel);
	  sock_printf(client->sockin, "<td><a href=\"%s\" target=\"_blank\">%s</a></td>\n", v, s);
	}
	else sock_printf(client->sockin, "<td>%s</td>\n", s);
	sprintf(s, "%s --&gt; %s:%d", ser->hostout[0] ? ser->hostout : "*", ser->peer, ser->port);
	if(*route) sprintf(v, "%s&cmd=1&index=%d", self, i); else sprintf(v, "%s?cmd=1&index=%d", self, i);
    if(ser->tuning==3 || ser->tuning==4) sock_printf(client->sockin, "<td><font color=%s>%s</font></td>\n",ser->resock>=0?"green":"red", s);
	else if(! ser->client) sock_printf(client->sockin, "<td><a href=\"%s#EDIT\">%s</a></td>\n", v, s);
	else sock_printf(client->sockin, "<td>%s</td>\n", s);
	if(ser->tunnel) sprintf(s,"%d", ser->tunnel); else *s='\0';
	sock_printf(client->sockin, "<td>%s</td>\n", s);
	str2html(s, ser->text);
	sock_printf(client->sockin, "<td>%s</td>\n", s);
	if(j%2==1) sock_printf(client->sockin, "</tr>");
  }
  if(n%2) sock_printf(client->sockin, "</tr>\n");
  sock_printf(client->sockin, "</table><br>\n");
  sock_printf(client->sockin, "</FORM>\n");

  http_get_value(h, "submit", s);
  if(*s=='\0' && cmd==1) cmd = 1; else cmd = 3;
  if(cmd==1) {
    i = http_get_int(h, "index", -1);
	if(i<0 || i>=numserver) cmd = 3;
  }
  if(cmd==1) {
    ser = servers + i;
	if(!ser->bind) cmd = 3;
	if(ser->client) cmd = 3;
  }

  sock_printf(client->sockin, "<a name=\"EDIT\">\n");
  sock_printf(client->sockin, "<FORM method=GET action=\"/socks\">\n");
  if(*route) sock_printf(client->sockin, "<input type=hidden name=route id=route value=\"%s\">\n", route);
  sock_printf(client->sockin, "<input type=hidden name=cmd id=ed_cmd value=%d>\n", cmd);
  if(cmd==1) sock_printf(client->sockin, "<input type=hidden name=index value=%d>\n", i);
  sock_printf(client->sockin, "<table border=1>\n");
  if(cmd==1) sprintf(s, "<a href=\"%s#EDIT\">New</a>", self); else *s='\0';
  sock_printf(client->sockin, "<tr><td>Type</td><td>External IP</td><td>Listen Port</td><td>Forward IP</td><td>Forward Port</td><td>Tunnel Port</td><td>Internal IP</td><td>%s</td></tr>\n", s);
  sock_printf(client->sockin, "<tr>");
  type = cmd==1 ? ser->type : 0;
  sock_printf(client->sockin, "<td><select name=type id=ed_type onchange=\"onchoose(this.value)\">\n");
  sock_printf(client->sockin, "<option value=0%s>auto</option>\n", option2str(type,0));
  sock_printf(client->sockin, "<option value=6%s>admin</option>\n", option2str(type,6));
  sock_printf(client->sockin, "<option value=9%s>tunnel</option>\n", option2str(type,9));
  sock_printf(client->sockin, "<option value=101%s>telnet</option>\n", option2str(type,101));
  sock_printf(client->sockin, "<option value=201%s>ssh</option>\n", option2str(type,201));
  sock_printf(client->sockin, "<option value=2%s>ftp</option>\n", option2str(type,2));
  sock_printf(client->sockin, "<option value=5%s>http</option>\n", option2str(type,5));
  sock_printf(client->sockin, "<option value=7%s>iiop</option>\n", option2str(type,7));
  sock_printf(client->sockin, "<option value=8%s>zcraw</option>\n", option2str(type,8));
  sock_printf(client->sockin, "<option value=501%s>switcher</option>\n", option2str(type,501));
  sock_printf(client->sockin, "<option value=801%s>ldap</option>\n", option2str(type,801));
  sock_printf(client->sockin, "<option value=601%s>smtp</option>\n", option2str(type,601));
  sock_printf(client->sockin, "<option value=701%s>pop3</option>\n", option2str(type,701));
  sock_printf(client->sockin, "<option value=901%s>oracle</option>\n", option2str(type,901));
  sock_printf(client->sockin, "<option value=1001%s>sybase</option>\n", option2str(type,1001));
  sock_printf(client->sockin, "<option value=1101%s>informix</option>\n", option2str(type,1101));
  sock_printf(client->sockin, "<option value=1201%s>imap</option>\n", option2str(type,1201));
  sock_printf(client->sockin, "<option value=1301%s>vnc</option>\n", option2str(type,1301));
  sock_printf(client->sockin, "<option value=1401%s>winterm</option>\n", option2str(type,1401));
  sock_printf(client->sockin, "<option value=409%s>hosting</option>\n", option2str(type,409));
  sock_printf(client->sockin, "<option value=1%s>tcp</option>\n", option2str(type,1));
  sock_printf(client->sockin, "</select></td>\n");
  if(cmd==1) sock_printf(client->sockin, "<td>%s</td>", ser->hostin);
  else sock_printf(client->sockin, "<td><input type=text name=hostin id=ed_hostin size=16></td>");
  if(cmd==1) sock_printf(client->sockin, "<td>%d</td>", ser->bind<0 ? 0 : ser->bind);
  else sock_printf(client->sockin, "<td><input type=text name=bind id=ed_bind size=6></td>");
  if(cmd==1) sprintf(s, " value=\"%s\"", ser->peer); else *s='\0';
  sock_printf(client->sockin, "<td><input type=text name=peer id=ed_peer size=16%s></td>", s);
  if(cmd==1) sprintf(s, " value=%d", ser->port); else *s='\0';
  sock_printf(client->sockin, "<td><input type=text name=port id=ed_port size=6%s></td>", s);
  if(cmd==1) sprintf(s, " value=%d", ser->tunnel); else *s='\0';
  sock_printf(client->sockin, "<td><input type=text name=tunnel id=ed_tunnel size=6%s></td>", s);
  if(cmd==1) sprintf(s, " value=\"%s\"", ser->hostout); else *s='\0';
  sock_printf(client->sockin, "<td><input type=text name=hostout id=ed_hostout size=16%s></td>", s);
  sock_printf(client->sockin, "<td><input type=submit name=submit value=\"%s\"></td>", cmd==1 ? "Modify" : "Insert");
  sock_printf(client->sockin, "</tr>\n");
  sock_printf(client->sockin, "<tr><td>Description</td>\n");
  if(cmd==1) sprintf(s, " value=\"%s\"", ser->text); else *s='\0';
  sock_printf(client->sockin, "<td colspan=6><input type=text name=text size=104%s></td>\n", s);
  if(cmd==1) strcpy(s, ser->logging ? " checked" : nullstr); else *s='\0';
  sock_printf(client->sockin, "<td><input type=checkbox name=log size=1 value=1%s>Log\n", s);
  if(cmd==1) strcpy(s, ser->single ? " checked" : nullstr); else *s='\0';
  sock_printf(client->sockin, "<input type=checkbox name=single size=1 value=1%s>Single", s);
  if(*route) sprintf(v, "%s&cmd=100", self); else sprintf(v, "%s?cmd=100", self);
  sock_printf(client->sockin, "<a href=\"%s\" target=\"_blank\">&nbsp;</a></td></tr>\n", v);
  sock_printf(client->sockin, "</table><br>\n");
  sock_printf(client->sockin, "</FORM>\n");

  for(i=0;i<numclient;i++) {
    cli = clients + i;
	if(cli->tid && cli != client) break;
  }
  sock_printf(client->sockin, "<hr size=2 noshade><br>\n");
  sock_printf(client->sockin, "<a name=\"CLIENT\">\n");
  sock_printf(client->sockin, "<FORM method=GET action=\"/socks\">\n");
  if(*route) sock_printf(client->sockin, "<input type=hidden name=route value=\"%s\">\n", route);
  sock_printf(client->sockin, "<input type=hidden name=cmd value=11>\n");
  sock_printf(client->sockin, "<table border=2 cellspacing=2 cellpadding=2 style=\"font-size:13px\" frame=\"box\">\n");
  sock_printf(client->sockin, "<tr bgcolor=\"#F1F5FB\" ><td colspan=10 align=center><a href=\"%s%s#CLIENT\"><B>Socket Connection List<B></a>\n", self, *route?"":"?");
  if(i<numclient) sock_printf(client->sockin, "<input type=submit name=submit value=Shutdown></td></tr>\n");
  else sock_printf(client->sockin, "</td></tr>\n");
  sock_printf(client->sockin, "<tr bgcolor=\"#F1F5FB\" >");
  sock_printf(client->sockin, "<td>Index</td>");
  sock_printf(client->sockin, "<td>Type</td>");
  sock_printf(client->sockin, "<td>Client from</td>");
  sock_printf(client->sockin, "<td>Forward to</td>");
  sock_printf(client->sockin, "<td>Connect Time</td>");
  sock_printf(client->sockin, "<td colspan=2>Client Bytes</td>");
  sock_printf(client->sockin, "<td colspan=2>Server Bytes</td>");
  sock_printf(client->sockin, "<td>Status</td>");
  sock_printf(client->sockin, "</tr>\n");
  for(i=n=0;i<numclient;i++) {
    cli = clients + i;
	if(! cli->tid) continue;
	if(cli == client) continue;
	n++;
	sock_printf(client->sockin, "<tr bgcolor=\"#FFFFFF\" >");
	if(cli != client) sprintf(s, "<input type=checkbox name=index value=%d size=1>%d", i, i); 
	else sprintf(s, "%d", i);
	sock_printf(client->sockin, "<td>%s</td>", s);
	sock_printf(client->sockin, "<td>%s</td>", type2str(cli->type));
	sprintf(s, "%s --&gt; %s:%d", cli->peer, cli->hostin, cli->bind);
	sock_printf(client->sockin, "<td>%s</td>", s);
	j = sprintf(s, "%s --&gt; %s:%d", cli->hostout, cli->peerout, cli->port);
	if(cli->dest) sprintf(s+j, " --&gt; %s:%d", cli->peerto, cli->dest);
	sock_printf(client->sockin, "<td>%s</td>", s);
	sprintt(s, cli->conntv);
	sock_printf(client->sockin, "<td>%s</td>", s);
	sock_printf(client->sockin, "<td>%.d</td>", cli->sendsize);
	sock_printf(client->sockin, "<td>%.d</td>", cli->ssize);
	sock_printf(client->sockin, "<td>%.d</td>", cli->readsize);
	sock_printf(client->sockin, "<td>%.d</td>", cli->rsize);
	switch(cli->status) {
	  case 0 : sock_printf(client->sockin, "<td>Initializing</td>");break;
	  case 1 : sock_printf(client->sockin, "<td>Idle = %ds</td>", cli->idle);break;
	  case 2 : sock_printf(client->sockin, "<td>Reading from %s:%d</td>", cli->peer, cli->bind);break;
	  case 3 : sock_printf(client->sockin, "<td>Sending to %s:%d</td>", cli->peerout, cli->port);break;
	  case 4 : sock_printf(client->sockin, "<td>Reading from %s:%d</td>", cli->peerout, cli->port);break;
	  case 5 : sock_printf(client->sockin, "<td>Sending to %s:%d</td>", cli->peer, cli->bind);break;
	  case 6 : sock_printf(client->sockin, "<td>Exiting</td>"); break;
	  case 7 : sock_printf(client->sockin, "<td>Waiting</td>\n"); break;
	  case 10 : sock_printf(client->sockin, "<td>Connecting to %s:%d</td>", cli->forward->peer, cli->forward->port); break;
	  default : sock_printf(client->sockin, "<td>Unknown(%d)</td>", cli->status);
	}
	cli->ssize = 0;
	cli->rsize = 0;
    sock_printf(client->sockin, "</tr>\n");
  }
  sock_printf(client->sockin, "</table><br>\n");
  sock_printf(client->sockin, "</FORM>\n");

  sock_printf(client->sockin, "</BODY>\n</HTML>\n");    
  return 0;  
}
