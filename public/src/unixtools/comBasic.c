#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/time.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include "comBasic.h"
#include "sysapi.h"
#include "sockets.h"

void c7recv_err_sys(char *msg, int ret_code, int err)
{
  output(10,"\n%s : Error(%s=%d) : %s ( %d )", AppName, msg, ret_code, strerror(err), err);
}

void printerr(char *msg)
{
int err = errno;
  output(10,"\n%s : Error(%s): %s ( %d )", AppName, msg, strerror(err), err);
} 

int checkerr(int ret, char *msg)
{
  if(ret<0) printerr(msg);
  return ret;
}

/* serListen initialize the sock communication for server
return 0 :success 
otherwise -1
*/

void clearsockerr(int sockfd)
{
int err, len;
  getsockopt(sockfd, SOL_SOCKET, SO_ERROR, (void *)&err, &len);
}

void closesocket(int sockfd)
{
char dummy[100];
  MarkAppSocket(sockfd, 0);
  shutdown(sockfd, 2);
  recv(sockfd, dummy, 100, 0);
  clearsockerr(sockfd);
  close(sockfd);
}

void setsockoptions(int sockfd)
{
char *p;
int lenth,v;
struct linger linger={ 0, 0 };

 p = getenv("TCP_BUFFER_SIZE");
 if(p) {
   lenth = atoi(p);
   setsockopt(sockfd,SOL_SOCKET,SO_RCVBUF,(void *)&lenth,sizeof(lenth));
   setsockopt(sockfd,SOL_SOCKET,SO_SNDBUF,(void *)&lenth,sizeof(lenth));
 }
 setsockopt(sockfd,SOL_SOCKET,SO_LINGER,(void *)&linger, sizeof(linger));
#ifdef sun
 v=60; setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPALIVE, (void*)&v, sizeof(v));
#else
 v=60; setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPIDLE, (void*)&v, sizeof(v));
 v=6;  setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPINTVL, (void *)&v, sizeof(v));
 v=10; setsockopt(sockfd, IPPROTO_TCP, TCP_KEEPCNT, (void *)&v, sizeof(v));
#endif
 clearsockerr(sockfd);
}

int ipName2Addr(int tcp, char *hostname, char *servicename, void *addr)
{
 struct sockaddr_in *seraddr = (struct sockaddr_in *)addr;
 static int locked = 0;
 struct hostent *host;
 struct servent *service;
 int port = 0;

  bzero(seraddr,sizeof(struct sockaddr_in));
  seraddr->sin_family=AF_INET;
  while(locked) poll(NULL, 0, 50); locked = 1;
  if(hostname) {
    if((host=gethostbyname(hostname))==NULL)
    { 
      locked = 0;
      return(-1);
    }
    memcpy(&(seraddr->sin_addr),host->h_addr_list[0],sizeof(struct in_addr));
  }
  else if(seraddr) {
    seraddr->sin_addr.s_addr=htonl(INADDR_ANY);
  }

  if(servicename) {
    if((port=atoi(servicename))==0) {
      if((service=getservbyname(servicename,tcp ? "tcp" : "udp"))==NULL)
      { 
		locked = 0;
        return(-1);
      }
      else port=ntohs(service->s_port);
	}
    if(seraddr) seraddr->sin_port=htons(port);
  }
  locked = 0;
  return port;

}

int tcpOpen()
{
int sockfd;
   if((sockfd=socket(AF_INET,SOCK_STREAM,0))<0) return -1;
   setsockoptions(sockfd);
   return sockfd;
}

int udpBind(int sockfd, struct sockaddr_in *addr)
{
   int ret_code=0;
   int reuse_addr=1;

  ret_code=setsockopt(sockfd,SOL_SOCKET,SO_REUSEADDR,(const char *)&reuse_addr,sizeof(reuse_addr));
  if(ret_code<0) return -1;
  ret_code=bind(sockfd,(struct sockaddr *)addr,sizeof(struct sockaddr_in));
  if(ret_code<0) return -1;
  return 0;
}

int tcpBind(int sockfd, struct sockaddr_in *addr)
{
  return udpBind(sockfd, addr);
}

int tcpListen(int sockfd)
{
  return listen(sockfd,1000);
}

int udpListen(char *servicename)
{
  int listen_sockfd;
   struct sockaddr_in seraddr;
   int ret_code=0;

  if(ipName2Addr(0, NULL, servicename, &seraddr)<0) {
    return(-1);
  }

  if((listen_sockfd=udpOpen())<0) {
	 printerr("socket"); return(-1);
  }

  ret_code=udpBind(listen_sockfd, &seraddr);
  if(checkerr(ret_code, "bind")<0) {
     close(listen_sockfd);
	  return(-1); 
   }

   return listen_sockfd;

}

int udpMulticast(int sockfd, char *local, char *multicast)
{
   int ret_code=0,i,n,loopback;
   struct ifreq ifs[64], *ifr;
   struct ifconf ifc;
   struct ip_mreqn mc;
   struct sockaddr_in *addr;
   struct in_addr mif;

  bzero(&mc, sizeof(mc));
  mc.imr_multiaddr.s_addr = inet_addr(multicast);
  mc.imr_address.s_addr = local ? inet_addr(local) : htonl(INADDR_ANY);
  mif = mc.imr_address;

  if(multicast) {
    ifc.ifc_len = sizeof(ifs);
    ifc.ifc_req = ifs;
    ret_code = ioctl(sockfd, SIOCGIFCONF, &ifc);
    if(checkerr(ret_code, "ioctl.SIOCGIFCONF")<0) return -1;
    n = ifc.ifc_len / sizeof(struct ifreq);
    for(i=0, ifr = ifs; i < n; i++, ifr++) {
	  if(ifr->ifr_addr.sa_family != AF_INET) continue;
	  addr = (struct sockaddr_in *)(&ifr->ifr_addr);
	  if(local) if(addr->sin_addr.s_addr != mc.imr_address.s_addr) continue;
	  ret_code = ioctl(sockfd, SIOCGIFINDEX, ifr);
      mc.imr_ifindex = ifr->ifr_ifindex;
      ret_code = setsockopt(sockfd, IPPROTO_IP,IP_ADD_MEMBERSHIP, &mc, sizeof(mc));
      if(ret_code<0) if(errno != EADDRINUSE) checkerr(ret_code, "setsockopt.ip_add_membership");
    }
  }
  else {
    ret_code = setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_IF, &mif, sizeof(mif));
    checkerr(ret_code, "setsockopt.ip_multicast_if");
    loopback = 1;
    ret_code = setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_LOOP, &loopback, sizeof(loopback));
    checkerr(ret_code, "setsockopt.ip_multicast_loop");
  }
  return 0;
}

int udpOpen()
{
int sockfd;
int so_broadcast = 1;
 if((sockfd=socket(AF_INET,SOCK_DGRAM,0))<0) return(-1);
 setsockopt(sockfd,SOL_SOCKET,SO_BROADCAST,&so_broadcast,sizeof(so_broadcast));
 MarkAppSocket(sockfd, 1);
 return sockfd;
}

int udpConnect(int sockfd, char *hostname, char *servicename)
{
  int ret_code=0;
  struct sockaddr_in seraddr;

  if(ipName2Addr(0, hostname, servicename, &seraddr) < 0) {
	  return(-1);
  }
   
  ret_code=connect(sockfd,(struct sockaddr*)&seraddr,sizeof(seraddr));
  if(ret_code < 0) {
     return(-1);
  }
  return(0);  
}

int udpSend(int sockfd, char *buff, int size, char *hostname, char *servicename)
{
struct sockaddr_in addr;
int ret_code;
  ret_code = ipName2Addr(0, hostname, servicename, &addr);
  if(ret_code < 0) return(-1);
  ret_code = sendto(sockfd, buff, size, 0, &addr, sizeof(struct sockaddr_in));
  return ret_code;
}

int udpRecv(int sockfd, char *buff, int size, char *hostname, char *servicename)
{
struct sockaddr_in addr;
socklen_t addrlen;
int ret_code;
  ret_code = recvfrom(sockfd, buff, size, 0, &addr, &addrlen);
  if(ret_code <= 0) return(ret_code);
  ipAddr2Name(hostname, servicename, &addr);
  return ret_code;
}

void udpClose(int sockfd)
{
  MarkAppSocket(sockfd, 0);
  shutdown(sockfd, 2);
  close(sockfd);
}

int serListen(int domain, char *servicename,int *pfd)
{  
  int listen_sockfd;
   struct sockaddr_in seraddr;
   int ret_code=0;

  *pfd = -1;
  ret_code = ipName2Addr(1, NULL, servicename, &seraddr);
  if(ret_code < 0) return(-1);

  if((listen_sockfd=tcpOpen())<0)
   return(-1);
  ret_code=tcpBind(listen_sockfd,&seraddr);
  if(checkerr(ret_code, "bind")<0) {
     close(listen_sockfd);
     return(-1); 
  }

  ret_code=tcpListen(listen_sockfd);
  if(checkerr(ret_code, "listen")<0) {
     close(listen_sockfd);
     return(-1); 
  }
         
 *pfd=listen_sockfd;
 MarkAppSocket(listen_sockfd, 1);
  return(0);
}


/* cliConnect initialize the sock communication for client
return 0 :success 
otherwise -1
*/
int tcpConnect(int sockfd, struct sockaddr_in *addr, int timeout)
{
    int n, ret_code=0;
    struct pollfd pollfd;

  if(!timeout) timeout = 5000;
  setSocketBlocking(sockfd, 0);
  ret_code=connect(sockfd,(struct sockaddr*)addr,sizeof(struct sockaddr_in));
  if(ret_code < 0) if(errno != EINPROGRESS) {
     return(-1);
  }
  if(ret_code < 0) {
    pollfd.fd = sockfd;
    pollfd.events = POLLOUT;
    for(n=(timeout+49)/50;n>0;n--) {
      ret_code = poll(&pollfd, 1, 50);
      if(ret_code<0) if(errno != EINTR) n=0; 
      if(ret_code==1) if(!(pollfd.revents&POLLOUT)) n=0;
      if(ret_code) break;
    }
    if(n==0) return(-1);
  }
  setSocketBlocking(sockfd, 1);
  return 0;
}


int cliConnect(int domain,char *hostname,char *servicename,int *pfd)
 {
    int sockfd;
    struct sockaddr_in seraddr;
    int ret_code=0;

  *pfd = -1;
  ret_code = ipName2Addr(1, hostname, servicename, &seraddr);
  if(ret_code < 0) return(-1);
	
  if((sockfd=tcpOpen())<0)
   return(-1);
   
  ret_code=tcpConnect(sockfd,&seraddr,0);
  if(ret_code < 0) {
     close(sockfd);   
     return(-1);
  }
  *pfd = sockfd;
  MarkAppSocket(sockfd, 1);
  return(0);  
 }
 
int setSocketBlocking(int sockfd, int blocking)
{
unsigned long opts;
int ret;
  opts = fcntl(sockfd, F_GETFL);
  if(blocking) opts&=~O_NONBLOCK; else opts|=O_NONBLOCK;
  ret=fcntl(sockfd, F_SETFL, opts);
  if(ret<0) clearsockerr(sockfd);
  return ret;
}

int _c7recv(int sockfd, char *buff, int size)
{
int ret, cnt, trap;

  for(cnt=trap=0;size>0;) {
 	 ret=recv(sockfd, buff, size, 0);
	 if(ret<0 && errno==EINTR) { if(++trap==10) return ret; else continue; }
	 if(ret<=0) return ret;
	 buff+=ret; size-=ret; cnt+=ret; trap=0;
  }
  return cnt;
}

int _c7recvx(int sockfd, char *buff, int size, int timeout)
{
int ret, cnt, trap;
struct pollfd pfd;

  pfd.fd = sockfd;
  pfd.events = POLLIN;

  for(cnt=trap=0;size>0 && timeout > 0;) {
    ret = poll( &pfd, 1, 1000);
    if(ret<0 && errno==EINTR) { if(++trap==10) return ret; else continue; }
    if(ret==1 && (pfd.revents&(POLLERR|POLLHUP|POLLNVAL))) ret=-1;
    if(ret<0) return ret;
    if(ret && !(pfd.revents&POLLIN)) ret=0;
    if(!ret) { timeout--;  trap=0; continue; }
    ret=recv(sockfd, buff, size, 0);
    if(ret<0 && errno==EINTR) { if(++trap==10) return ret; else continue; }
    if(ret<0) return -1;
    if(!ret) break;
    buff+=ret;  size-=ret;  cnt+=ret; trap=0;
  }
  return cnt;
}

int c7recvmsg(int sockfd, char *buff)
{
short len;
  if(_c7recv(sockfd, buff, 2)<2) return -1;
  CHAR_SHORT(buff, len);
  if(_c7recv(sockfd, buff+2, len-2)<len-2) return -1;
  return len;
}

/*
send flag to server to indicate what kind of message it will process.
*/
int cliRegister(int sockfd,int type)
{   char buff[1];
    buff[0]=type;  
    if(send(sockfd,buff,1,0)!=1)
    	return(-1);
    if(recv(sockfd,buff,1,0)!=1)
       return(-1);
    return(0);
}


int setMonFilter(char *buff,int num, int *linkid,int monmask)
{ 
char *p = buff;
  
  SHORT_CHAR(p, monmask); p+=2;
  if(num>32) num=32;
  if(num<0) num=0;
  SHORT_CHAR(p, num); p+=2;
  for(;num>0;num--, linkid++, p+=2)  SHORT_CHAR(p,*linkid); 
  return p-buff;
}

/* the server set the configuration of remote collect site,
the remote collect site get it.

 return 0 success
-1 unsucces
*/

int getDcsConfig(int sockfd, char *ipaddr, RM_LINKMAP_TYPE *dcs_config)
{ 
   const int size_linkmap=sizeof(RM_LINKMAP_TYPE);
   int i;
   int lenth;
   
  struct sockaddr_in local_addr;
  int size_sockaddr=sizeof(local_addr);

   char buff[20];
   
   *buff=1;

  if(!ipaddr) {
  if(getsockname(sockfd,(struct sockaddr *)&local_addr,&size_sockaddr)<0)
    { c7recv_err_sys("getsockname",-1,errno); 
      return -1;
    }
  if((ipaddr=inet_ntoa(local_addr.sin_addr))==NULL)
    {  c7recv_err_sys("inet_ntoa",-1,errno); 
      return -1;
    }
  }
  strcpy(buff+1, ipaddr);


  /* send the ip_address of dcs */
  lenth=1+strlen(buff+1)+1;
  if(send(sockfd,buff,lenth,0)<lenth)
    return(-1);
  
  /* recv configuration of dcs */
  if(recv(sockfd,buff,2,0)<2)
    return(-1);
   CHAR_SHORT(buff,lenth);
   if(lenth<=0) return lenth;

   output(0,"\n\tReceiving %d configurations for '%s' from center host...", lenth, ipaddr);
   for(i=0;i<lenth;i++)
     { if(c7recv(sockfd,dcs_config+i,size_linkmap)<size_linkmap)
         return(-1);

     }

   return(lenth);
}


void iniRM_LINKMAPS(RM_LINKMAP_TYPE *dc_configs,int nums)
{
int i;

for(i=0;i<nums;i++)
  {
    dc_configs[i].linkId[0]='\0';
    dc_configs[i].spc[0]='\0';
    dc_configs[i].cardNumber[0]='\0';
    dc_configs[i].lineNumber=255;
    dc_configs[i].slotNumber=255;
    dc_configs[i]._slotNum=255;
    dc_configs[i].rServerIP[0]='\0';
  }

}

/*
check to see if message in buff[0..curr_posi-1] is complete 
return 0: not complete
return 1:complete  then buff[0..next_msg_posi-1] are messages
return -1: message's lenth is not correct

*/

int checkMsgLenth(char *buff, int lenth)
{
short li;
  li = buff[MSG_POS_LI]&0x3f;
  if(li == 63) return lenth>=63;
  return lenth == li;
}

int checkBuff(char *buff,int curr_posi,int *next_msg_posi)
{ short mess_lenth;
  
  *next_msg_posi = 0;
  for(;curr_posi>=2;buff+=mess_lenth, curr_posi-=mess_lenth)
     {
	CHAR_SHORT(buff, mess_lenth);
	if(mess_lenth < 0) return(-1);
   if(!mess_lenth) mess_lenth = 2;
	if(mess_lenth > curr_posi) break;
	*next_msg_posi += mess_lenth;
     }
   return(*next_msg_posi > 0);
}


int checkBuffWithTimeStamp(char *buff,int curr_posi,int *next_msg_posi)
{
struct timeval t;
short mess_lenth=0;
int sec;
short msec;
  
 *next_msg_posi=0;
 gettimeofday(&t, NULL);
 sec = htonl(t.tv_sec);
 msec = htons(t.tv_usec/1000);
 
 for(;curr_posi>=MIN_MSG_LEN;buff+=mess_lenth, curr_posi-=mess_lenth)
     {
	CHAR_SHORT(buff, mess_lenth);
	if(mess_lenth < 0) return(-1);
   if(!mess_lenth) mess_lenth = 2;
	if(mess_lenth > curr_posi) break;
   if(mess_lenth > 15) {
	  memcpy(buff+MSG_POS_TIME, &sec, 4);
	  memcpy(buff+MSG_POS_MSEC, &msec, 2);
   }
	*next_msg_posi += mess_lenth;
     }

 return(*next_msg_posi > 0);
}

int clearBuff(char *buff,int *curr_posi,int *next_msg_posi,int flag)
{
  if(flag == F_DISCARD_ALL) *curr_posi = *next_msg_posi = 0;
  else {
    *curr_posi -= *next_msg_posi;
    if(*curr_posi > 0) memcpy(buff, buff+*next_msg_posi, *curr_posi);
    *next_msg_posi = 0;
  }
  return 0;
}

