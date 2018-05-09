#ifndef _SYSAPI_H_
#define _SYSAPI_H_

#include <pthread.h>
#include <time.h>
#include <stdio.h>

typedef void (*dchandler_t)(int cmd, char *para);
typedef void (*dchandler_t4)(FILE *fp, char *device, int cmd, char *para);
typedef int (*fthandler_t)(int sig, pthread_t tid, pthread_t maintid);

#ifdef __cplusplus
extern "C" {
#endif

#define OL_DEBUG   0
#define OL_GENERAL 1
#define OL_WARNING 2
#define OL_FATAL   3

#define appHint *apphint_r()

extern FILE *OutFile;
extern int appVersion;
extern int appRunning;
extern int appProgress;
extern int appTimeout;
extern int appBranch;
extern int appIndicator;
extern int AppHint;
extern time_t appStartTime;
extern int InstanceCheck;
extern char AppName[];
extern int RunMode;

extern int cftime(char *s, char *format, const time_t *clock);
extern char *sprintt(char *timestr, time_t t);
extern char *sprinttm(char *timestr, struct tm *tm);
extern char *sprinttv(char *timestr, double tv);
extern void RedirectOutput(char *filename);
extern void output(int level, char *fmt,...);
extern int  fdprintf(int fd, const char *fmt, ...);
extern int  sockprintf(int sockfd, const char *fmt, ...);
extern int  _fwrite(FILE *fp, char *data, int size);
extern int  _fputs(FILE *fp, char *s);
extern int  _fprintf(FILE *fp, const char *fmt, ...);
extern int  _fclose(FILE *fp);
extern void flush();
extern void Sleep(int fd, int msec);
extern void PrintPeerAddress(int sockfd, char *addr);
extern void PrintHostAddress(int sockfd, char *addr);
extern void hexprint(char *buff, int len);
extern int  StopApplication(char *appname, int timeout);
extern int  CheckApplication(char *appname);

#if (_COMBASIC_VERSION >= 4 && !defined(_COMBASIC_IMPLEMENTATION) )

#define SendAppCommand(appname, cmd, para) 	SendAppCommand4((appname), (cmd), (para), NULL)
#if (_COMBASIC_VERSION >= 5)
#define SetAppCommandHandler 						SetAppCommandHandler5
#else
#define SetAppCommandHandler 						SetAppCommandHandler4
#endif
#define SetAppOutputLevel 							SetAppOutputLevel4
#define StartFailSafeRoutine						StartFailSafeRoutine4

#else

extern int  SendAppCommand(char *appname, int cmd, char *para);
extern int  SetAppCommandHandler(dchandler_t handler);
extern int  SetAppOutputLevel(char *appname, int level);
extern int  StartFailSafeRoutine(void (*routine)(void));

#endif

extern int  SendAppCommand5(char *appname, int cmd, char *para, char *device);
extern int  SendAppCommand4(char *appname, int cmd, char *para, char *device);
extern int  SetAppCommandHandler4(dchandler_t4 handler);
extern int  SetAppCommandHandler5(dchandler_t4 handler);
extern int  SetAppCommandHandler6(dchandler_t4 handler);
extern int  SetAppOutputLevel4(char *appname, char *level);
extern int  StartFailSafeRoutine4(void (*routine)(void), void (*cleanup)(void));
extern int  HookAppOutput(char *appname, char *filename);
extern int  SetAppFatalHandler(fthandler_t handler);
extern int  SetAppTimerHandler(void (*handler)());
extern void  InstallAppSignalHandler();
extern int  StartApplication();
extern int  RunApplication(int argc, char *argv[], char *usage);
extern int  *apphint_r();

#ifdef __cplusplus
	   }
#endif

#endif


