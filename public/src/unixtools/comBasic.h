#ifndef _COMBASIC_H
#define _COMBASIC_H

#if defined(sparc) && defined(sun) 
#include <thread.h>
#include <synch.h>
#elif !defined(__linux__)
#include <memory.h>
#endif
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <unistd.h>
#include <strings.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>

#define F_DISCARD_MESSAGE 1
#define F_DISCARD_ALL 2

#define REQ_TYPE_END 1
#define REQ_TYPE_RMT 2
#define REQ_TYPE_MON 3
#define REQ_TYPE_RMT_GET_CONFIG 7
#define REQ_TYPE_CONFIG_CHANGED 8

#define MSG_TYPE_MTP	0x80
#define MSG_TYPE_SCCP	0x83
#define MSG_TYPE_TUP	0x84
#define MSG_TYPE_ISUP	0x85
	
#define MONMASK(msgtype) (unsigned)(0x0001<<(msgtype&0x0f))

    /* MSG_LENTH_AMM = MSG_LENTH_BF_LFLD+MSG_LENTH_AF_FLD+1 */
#define MAX_MSG_LEN 	290 /* 272+MSG_LENTH_AMM+MSG_LENTH_INS     */
#define MIN_MSG_LEN     18  /* MSG_LENTH_INS+MSG_LENTH_AMM */
#define MSG_LENTH_INS   15  /* the lenth include timestamp link num and lenth */
#define MSG_LENTH_HEAD  17

#define MSG_POS_LEN	0
#define MSG_POS_SPC	2
#define MSG_POS_LINKID	5
#define MSG_POS_TIME	7
#define MSG_POS_MSEC	13

#define MSG_START	15

#define MSG_POS_FSN	0
#define MSG_POS_BSN	1
#define MSG_POS_LI	2
#define MSG_POS_SIO	3
#define MSG_POS_SIF	4
#define MSG_POS_DPC	4
#define MSG_POS_OPC	7
#define MSG_POS_SLS	10
#define MSG_POS_TUP_CIC		10
#define MSG_POS_ISUP_CIC	11
#define MSG_POS_TUP_TYPE	12
#define MSG_POS_ISUP_TYPE	13

#define SHORT_CHAR(buff,lenth) \
{ *(buff)=(lenth) % 256;    \
  *((buff)+1)=(lenth) /256; \
}

#define CHAR_SHORT(buff,lenth) \
{  lenth=((unsigned char)*((buff)+1))*256+((unsigned char)*(buff)); \
}

#define CHAR_SPC(buff) \
((unsigned char)*((buff)+2)*65536+(unsigned char)*((buff)+1)*256+(unsigned char)*(buff))

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _rm_linkmap{
  unsigned char  linkId[2];
  unsigned char  spc[4];
  unsigned char  cardNumber[2];
  unsigned char  lineNumber;
  unsigned char  slotNumber;
  unsigned char  _slotNum;  /* _slocNum=0 or _slocNum=1 for address convience */
  unsigned char  rServerIP[30];
} RM_LINKMAP_TYPE;

extern int ipName2Addr(int tcp, char *hostname, char *servicename, void *addr);
extern int ipAddr2Name(char *hostname, char *servicename, void *addr);

extern int udpListen(char *servicename);
extern int udpMulticast(int sockfd, char *local, char *multicast);
extern int udpOpen();
extern int udpConnect(int sockfd, char *hostname, char *servicename);
extern int udpSend(int sockfd, char *buff, int size, char *hostname, char *servicename);
extern int udpRecv(int sockfd, char *buff, int size, char *hostname, char *servicename);
extern void udpClose(int sockfd);
extern int udpBind(int sockfd, struct sockaddr_in *addr);

extern int tcpOpen();
extern int tcpBind(int sockfd, struct sockaddr_in *addr);
extern int tcpListen(int sockfd);
extern int tcpConnect(int sockfd, struct sockaddr_in *addr, int timeout);

extern int serListen(int domain,char *servicename,int *pfd);
extern int cliConnect(int domain,char *hostname,char *servicename,int *pfd);
extern int cliRegister(int sockfd,int flag);
extern int setSocketBlocking(int sockfd, int blocking);
extern int _c7recv(int sockfd, char *buff, int size);
extern int _c7send(int sockfd, char *buff, int size);
extern int _c7recvx(int sockfd, char *buff, int size, int timeout);
extern int _tcpsend(int sockfd, char *buff, int size);
extern int c7recvmsg(int sockfd, char *buff);
extern void clearsockerr(int sockfd);
extern void setsockoptions(int sockfd);
extern void closesocket(int sockfd);
extern int checkMsgLenth(char *buff, int lenth);
extern int checkBuff(char *buff,int curr_posi,int *next_msg_posi);
extern int checkBuffWithTimeStamp(char *buff,int curr_posi,int *next_msg_posi);
extern int clearBuff(char *buff, int *curr_posi, int *next_msg_posi, int flag);

#ifdef VERSION2
extern int setMonFilter(int sockfd, int num, int *linkid, int monmask);
#else
extern int setMonFilter(char *buff,int num, int *linkid,int monmask);
#endif

extern int getDcsConfig(int sockfd, char *ipaddr, RM_LINKMAP_TYPE *dcs_config);

extern void c7recv_err_sys(char *msg,int retcode,int errno_num);
extern void printerr(char *msg);
extern int  checkerr(int ret, char *msg);
extern void iniRM_LINKMAPS(RM_LINKMAP_TYPE *dcs_configs,int nums);

#ifdef __cplusplus
}
#endif

#define c7recv(sockfd, buff, size)	_c7recv((sockfd), (char *)(buff), (size))
#define c7recvx(sockfd, buff, size, timeout)	_c7recvx((sockfd), (char *)(buff), (size), (timeout))
#define c7send(sockfd, buff, size)  _c7send((sockfd), (char *)(buff), (size))
#define tcpsend(sockfd, buff, size)  _tcpsend((sockd), (char *)(buff), (size))

#endif
