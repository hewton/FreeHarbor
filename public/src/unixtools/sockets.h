#ifndef _SOCKETS_H_
#define _SOCKETS_H_

#ifdef __cplusplus
extern "C" {
#endif

extern void MarkAppSocket(int sockfd, int flag);
extern int _c7send(int sockfd, char *buff, int size);
extern int _tcpsend(int sockfd, char *buff, int size);

#ifdef __cplusplus
}
#endif

#endif
