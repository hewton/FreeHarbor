#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdlib.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <stropts.h>
#ifndef  __linux__
#ifdef  sun
#define  _STRUCTURED_PROC	1
#endif
#include <sys/procfs.h>
#endif
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/poll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#define _COMBASIC_IMPLEMENTATION
#include "sysapi.h"
#include "sockets.h"

FILE *OutFile;

static int OutputLevel=0x0ffe;
int  appRunning=0;
int  appVersion=0x03130000;
int  appIndicator=0;
int  appProgress=0;
int  appTimeout=60;
int  appBranch=0;
int  AppHint=0;
static int  appTrapping=0;
static int  _appProgress=0;
time_t appStartTime=0;
static int _timezone=0;
static int _appTimeout=0;
static int _appTrapping=0;
static pthread_t appFailSafeThread=0;
struct sockentry_t {
  short active;
  short cur;
  short rts;
  char  *buff; 
};
static struct sockentry_t _sockarray[256] = { { 0, 0, 0, NULL } };

dchandler_t appCommandHandler=NULL;
dchandler_t4 appCommandHandler4=NULL;
dchandler_t4 appCommandHandler5=NULL;
dchandler_t4 appCommandHandler6=NULL;
fthandler_t appFatalHandler = NULL;
void (*appTimerHandler)() = NULL;

char AppName[30]="";
int  RunMode=0;
int  InstanceCheck=1;
int  appMainThreadId=0;
static int apphints[101];

static int TCPCacheSize=16000;
static int TCPInstant=0;

#define _WORKDIR (getenv("HOME")?getenv("HOME"):"/tmp")
#define checkfp(fp)	(!(fp) ? 0 : (int)(fp)>0 && (int)(fp)<32768 ? 1 : *((int *)(fp))==(int)(fp) ? 3 : 2)
#define is_leap_year(year) (((year)%4==0 && (year)%100) || (year)%400==0)

#ifndef sun
#ifdef __cplusplus
extern "C" {
#endif

extern int cftime(char *s, char *format, const time_t *clock);
extern int ascftime(char *s, const char *format,  const  struct  tm *timeptr);

#ifdef __cplusplus
}
#endif

int cftime(char *s, char *format, const time_t *clock)
{
struct tm tm;
  localtime_r(clock, &tm);
  return strftime(s, 40, format, &tm);
}

int ascftime(char *s, const char *format,  const  struct  tm *timeptr)
{
  return strftime(s, 40, format, timeptr);
}

#ifndef __linux__
#define sig2str(signum, str)	sprintf((str), "%d", (signum))
#endif
#endif

#ifdef __linux__
#ifdef __cplusplus
extern "C" {
#endif

extern struct tm *localtime_r(const time_t *clock, struct tm *res);
#define sig2str(signum, str)	strcpy((str), _sys_siglist[(signum)])

#ifdef __cplusplus
}
#endif

struct tm *localtime_r(const time_t *clock, struct tm *res)
{
struct tm *tm;
  tm = localtime(clock);
  if(res) { *res = *tm; tm=res; }
  return tm;
}

#endif

int *apphint_r()
{
  return apphints + abs(pthread_self()%101);
}

void i2s(char *s, int len, int d)
{
  for(;len>0;len--,d/=10) s[len-1]='0'+d%10;
}

char *sprintt(char *timestr, time_t t)
{
int n, sec, year, month, day;
  if(!t) { *timestr='\0'; return timestr; }
  sec=t - _timezone;
  day=sec/86400;
  sec%=86400;
  for(year=1970;;day-=n,year++) {
    n=is_leap_year(year)?366:365;
    if(day<n) break;
  }
  for(month=1;;day-=n,month++) {
    n=month==2? (is_leap_year(year) ? 29 : 28) : (month==4 || month==6 || month==9 || month==11 ? 30 : 31);
    if(day<n) break;
  }
  i2s(timestr, 4, year); timestr[4]='-';
  i2s(timestr+5, 2, month); timestr[7]='-';
  i2s(timestr+8, 2, day+1); timestr[10]=' ';
  i2s(timestr+11, 2, sec/3600); timestr[13]=':';
  i2s(timestr+14, 2, sec/60%60); timestr[16]=':';
  i2s(timestr+17, 2, sec%60);
  timestr[19]='\0';
  return timestr;
}

char *sprinttm(char *timestr, struct tm *tm)
{
  return sprintt(timestr, mktime(tm));
}

char *sprinttv(char *timestr, double tv)
{
time_t t;
int msec;
  t = tv;
  sprintt(timestr, t);
  msec = ( tv - t ) * 1000; 
  timestr[19]='.';
  i2s(timestr+20, 3, msec);
  timestr[23]='\0';
  return timestr;
}

int _tcpsend(int sockfd, char *buff, int size)
{
int ret;
  ret = send(sockfd, buff, size, 0);
  if(ret<0) if(errno==EINTR) ret = send(sockfd, buff, size, 0);
  return ret;
}

void MarkAppSocket(int sockfd, int flag)
{
struct sockentry_t *s;
  if(sockfd<0 || sockfd>=256) return;
  s = _sockarray + sockfd;
  if(!flag) while(s->rts) if(_c7send(sockfd, NULL, 0)<=0) break;
  s->cur = s->rts = 0;
  if(s->buff) { free(s->buff); s->buff = NULL; }
  s->active = flag;
}

int _c7send(int sockfd, char *buff, int size)
{
struct sockentry_t *s;
int ret;
  if(sockfd<0) return -1;
  if(TCPInstant) return _tcpsend(sockfd, buff, size);
  if(sockfd>=256) return size ? _tcpsend(sockfd, buff, size) : 0;
  s = _sockarray + sockfd;
  if(!s->active) return size ? _tcpsend(sockfd, buff, size) : 0;
  if(!size) {
    while(s->rts) {
      ret=_tcpsend(sockfd, s->buff+s->cur, s->rts);
      if(ret<=0) return ret;
      s->rts -= ret; s->cur += ret;
    }
    return 0;
  }
  while(s->rts && size+s->rts > TCPCacheSize) {
    ret=_tcpsend(sockfd, s->buff+s->cur, s->rts);
    if(ret<=0) return ret;
    s->rts -= ret; s->cur += ret;
  }
  if(size > TCPCacheSize) return _tcpsend(sockfd, buff, size);
  if(! s->buff) {
    s->buff = (char *)malloc(TCPCacheSize);
    if(! s->buff) return _tcpsend(sockfd, buff, size);
  }
  if(s->cur+s->rts+size > TCPCacheSize) {
    if(s->rts) memcpy(s->buff, s->buff+s->cur, s->rts);
    s->cur = 0;
  }
  memcpy(s->buff+s->cur+s->rts, buff, size);
  s->rts += size;
  return size;
}

void fdflush(int fd)
{
  fsync(fd);
}

void flush()
{
  fdflush(1);
}

static int _vfdprintf(int fd, int size, const char *fmt, va_list arg)
{
char s[size+1];
int len;
  len = vsnprintf(s, size+1, fmt, arg);
  if(len <= size) return write(fd, s, len);
  return len;
}

static int vfdprintf(int fd, const char *fmt, va_list arg)
{
int len;
  len = _vfdprintf(fd, 1024, fmt, arg);
  if(len <= 1024) return len;
  return _vfdprintf(fd, len, fmt, arg);
}

int fdprintf(int fd, const char *fmt, ...)
{
va_list arg;
char *s;
int len;
  va_start(arg, fmt);
  if(fmt) len = vfdprintf(fd, fmt, arg);
  else { s=va_arg(arg, char *); len = write(fd, s, strlen(s)); }	  
  va_end(arg);
  return len;
}

static int _vsockprintf(int sockfd, int size, const char *fmt, va_list arg)
{
char s[size+1];
int len;
  len = vsnprintf(s, size+1, fmt, arg);
  if(len <= size) return send(sockfd, s, len, 0);
  return len;
}

static int vsockprintf(int sockfd, const char *fmt, va_list arg)
{
int len;
  len = _vsockprintf(sockfd, 1024, fmt, arg);
  if(len <= 1024) return len;
  return _vsockprintf(sockfd, len, fmt, arg);
}

int sockprintf(int sockfd, const char *fmt, ...)
{
va_list arg;
char *s;
int len;
  va_start(arg, fmt);
  if(fmt) len = vsockprintf(sockfd, fmt, arg);
  else { s=va_arg(arg, char *); len = send(sockfd, s, strlen(s), 0); }	  
  va_end(arg);
  return len;
}

struct shmctl_t {
  int ident;
  int start;
  int limit;
};

int _fwrite(FILE *fp, char *data, int len)
{
struct shmctl_t *ctl;
  switch(checkfp(fp)) {
  case 1 :
    len = write((int)fp, data, len);  
    break;
  case 2 :
    len = fwrite(data, 1, len, fp);
    break;
  case 3 :
    ctl = (struct shmctl_t *)fp;
    if(len > ctl->limit) len = ctl->limit;
    if(!len) break;
    memcpy((char *)fp+ctl->start, data, len);
    ctl->start += len;
    ctl->limit -= len;
    break;
  default : len = 0;
  }
  return len;
}

int _fputs(FILE *fp, char *s)
{
  return s ? _fwrite(fp, s, strlen(s)) : 0;
}

int _fprintf(FILE *fp, const char *fmt, ...)
{
va_list arg;
int len;
struct shmctl_t *ctl;
  va_start(arg, fmt);
  if(!fmt) len=_fputs(fp, va_arg(arg, char *));
  else switch(checkfp(fp)) {
  case 1 : len = vfdprintf((int)fp, fmt, arg); break;
  case 2 : len = vfprintf(fp, fmt, arg); break;
  case 3 :
    ctl = (struct shmctl_t *)fp;
    len = vsnprintf((char *)fp+ctl->start, ctl->limit, fmt, arg);
    if(len > ctl->limit) len = ctl->limit;
    ctl->start += len;
    ctl->limit -= len;
    break;
  default : len = 0; 
  }
  va_end(arg);
  return len;
}

int _fclose(FILE *fp)
{
  switch(checkfp(fp)) {
    case 1 : close((int)fp); 
    case 2 : fclose(fp);
  }
  return 0;
}

void Sleep(int fd, int msec)
{
struct pollfd pfd;
  pfd.fd=fd;
  pfd.events=POLLIN;
  poll(&pfd, 1, msec);
}

void RedirectOutput(char *filename)
{
int fd;
  if(!filename) return;
  fd=open(filename, O_CREAT|O_TRUNC|O_WRONLY, 0664);
  if(fd <= 0) { perror("open"); return; }
  dup2(fd, 1);
  close(fd);
}

static void _SetOutputLevel(char *level)
{
char *p;
int lo, hi;
  if(*level=='\0') return;
  p = strchr(level, '-');
  if(!p) lo=hi=atoi(level);
  else {
    *p++='\0';
    if(*level) lo=atoi(level); else lo=0;
    if(*p) hi=atoi(p); else hi=9;
  }
  for(;lo<=hi;lo++) OutputLevel|=(1<<lo);
}

void SetOutputLevel(char *level)
{
char *p;
  OutputLevel=0;
  while((p=strchr(level,','))) { *p++='\0'; _SetOutputLevel(level); level=p; }
  if(*level) _SetOutputLevel(level);
}

void output(int level, char *fmt,...)
{
int opflush = 0;
int optime = 0;
char timestr[40+1];
va_list arg;
  if(level>99) { opflush=1; level-=100; }
  if(level>9) { optime=1; level-=10; }
  if(!(OutputLevel & (1<<level))) return;
  va_start(arg, fmt);
  if(optime) {
	 while(*fmt=='\r' || *fmt=='\n') write(1, fmt++, 1);
	 fdprintf(1, "%s : ", sprintt(timestr, time(NULL)));
  }
  vfdprintf(1, fmt, arg);
  va_end(arg);
  if(opflush) flush();
}


static void _itonb(unsigned int u, unsigned char *b)
{
#ifdef linux
  b[3] = (u>>24)&0x0ff;
  b[2] = (u>>16)&0x0ff;
  b[1] = (u>>8)&0x0ff;
  b[0] = u&0x0ff;
#else
  b[0] = (u>>24)&0x0ff;
  b[1] = (u>>16)&0x0ff;
  b[2] = (u>>8)&0x0ff;
  b[3] = u&0x0ff;
#endif
}

int ipAddr2Name(char *hostname, char *servicename, void *addr)
{
struct sockaddr_in *inaddr = (struct sockaddr_in *)addr;
unsigned char b[4];
int port;
  if(hostname) {
    _itonb(inaddr->sin_addr.s_addr, b);
    sprintf(hostname, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
  }
  port = ntohs(inaddr->sin_port);
  if(servicename) {
	sprintf(servicename, "%d", port);
  }
  return port;
}

void PrintPeerAddress(int sockfd, char *addr)
{
struct sockaddr_in inaddr;
int addrlen=sizeof(inaddr);
char ipaddr[16];
  getpeername(sockfd, (struct sockaddr *)&inaddr, &addrlen);
  if(!addr) addr = ipaddr;
  ipAddr2Name(addr, NULL, &inaddr);
  if(addr == ipaddr) output(11,"\n%s : Accepted connection from %s", AppName, addr);
}

void PrintHostAddress(int sockfd, char *addr)
{
struct sockaddr_in inaddr;
int addrlen=sizeof(inaddr);
  getsockname(sockfd, (struct sockaddr *)&inaddr, &addrlen);
  ipAddr2Name(addr, NULL, &inaddr);
}

void hexprint(char *buff, int len)
{
unsigned char c;
  if(!(OutputLevel&1)) return;
  output(0,"len=%d:",len);
  for(c=*buff++;len>0;len--,c=*buff++) output(0," %02x",c);
  output(0,"\n");
}

static void *appFailSafeThreadRoutine(void (*routine)(void))
{
  InstallAppSignalHandler();
  (*routine)(); 
  return NULL;
}

static int checkAppHanging();

int StartFailSafeRoutine4(void (*routine)(void), void (*cleanup)(void))
{
  if(pthread_create(&appFailSafeThread, NULL, (void* (*)(void*))appFailSafeThreadRoutine, routine)) return 0;
  for(;appRunning;sleep(1)) {
    if(pthread_kill(appFailSafeThread, 0)) break;
    if(checkAppHanging()) { 
       pthread_kill(appFailSafeThread, SIGKILL); 
       output(11, "\n%s : Terminated gracefully hanging up at %d : %d", AppName, AppHint, apphints[abs(appFailSafeThread%101)]);
       break;
    }
  }
  if(appRunning) if(cleanup) (*cleanup)();
  return 0;
}

int StartFailSafeRoutine(void (*routine)(void))
{
  return StartFailSafeRoutine4(routine, NULL);
}

static int defaultFatalHandler(int sig, pthread_t tid, pthread_t maintid)
{
char signame[30];
    if(!appRunning) return 1;
    sig2str(sig, signame);
    output(11, "\n%s ( tid=%c%d, main=%d ) catched fatal signal %s (%d) at %d : %d", AppName, tid==appFailSafeThread?'*':'\0', tid, maintid, signame, sig, AppHint, appHint);
    if(appCommandHandler6) (*appCommandHandler6)((FILE *)1, "", 0, "");
    else if(appCommandHandler5) (*appCommandHandler5)((FILE *)1, "", 0, "");
    else if(appCommandHandler4) (*appCommandHandler4)(stdout, "", 0, "");
    else if(appCommandHandler) (*appCommandHandler)(0, "");
    if(tid != appFailSafeThread) return 1;
    return 0;
}

static struct sigaction appSigAction;

static void  shutdownAll()
{
int i;
struct stat st;
  for(i=0;i<256;i++) 
    if(_sockarray[i].active) { if(!fstat(i,&st)) if(S_ISSOCK(st.st_mode)) shutdown(i,2); }
}

static void shutdownApplication()
{
    if(!appRunning) _exit(0);
    appRunning=0; 
    shutdownAll();
}

static int  checkAppHanging()
{
   if(!_appProgress) { _appProgress = appProgress; return 0; }
   if(_appProgress!=appProgress || !appIndicator) { _appProgress=appProgress; _appTimeout=0; return 0; }
   if(_appTimeout++ < appTimeout) return 0;
   _appTimeout = 0;
   return 1;
}

static void  defaultCommandHandler(FILE *fp, char *device, int cmd, char *para)
{
  switch(cmd) {
    case -1: RedirectOutput(device); break;
    case -2: SetOutputLevel(para); break;
    case -3: 
      if(checkAppHanging()) { 
        output(11, "\n%s : Terminated gracefully hanging up at %d : %d", AppName, AppHint, *apphint_r());
        shutdownApplication(); 
      }
      break;
    default: break;
  }
}

void  appSignalHandler(int sig, siginfo_t *sip, void *uap)
{
int shmid, cmd, fd, excode;
pthread_t tid;
char *shmaddr, *device, *param;
char signame[100];
FILE *fp;

  switch(sig) {
  case SIGTERM: 
    shutdownApplication();
    break;
  case SIGINT:
    if(appTrapping) break;
    appTrapping = 1;
    shmid=shmget(getpid(), 0, 0660);
    if(shmid==-1 && !RunMode && errno == ENOENT) { shutdownApplication(); appTrapping=0; break; }
    if(shmid==-1) { appTrapping=0; break; }
    shmaddr=(char *)shmat(shmid, NULL, 0660);
    if(!shmaddr) { appTrapping=0; break; }
    cmd=(signed char)shmaddr[1];
    device = shmaddr+2;
    param = device + strlen(device) + 1;
    if(cmd<0) { 
      defaultCommandHandler((FILE *)1, device, cmd, param); 
      fdflush(1); 
    }
    else if(appCommandHandler6) {
      struct shmctl_t *ctl = (struct shmctl_t *)(shmaddr+1024);
      ctl->ident = (int)ctl;
      (*appCommandHandler6)((FILE *)ctl, device, cmd, param);
    }
    else if(appCommandHandler5) {
      fd = open(device, O_RDWR|O_CREAT|O_TRUNC, 0660);
      if(fd==-1) fd = 1;
      (*appCommandHandler5)((FILE *)fd, device, cmd, param);
      if(fd!=1) close(fd); else fdflush(1);
    }
    else if(appCommandHandler4) {
      fp = fopen(device, "w"); 
      if(!fp) fp = stdout;
      (*appCommandHandler4)(fp, device, cmd, param);
      if(fp!=stdout) fclose(fp); else fflush(fp);
    }
    else if(appCommandHandler) {
      (*appCommandHandler)(cmd, cmd?param:device);
    }
	*shmaddr='1'; shmdt(shmaddr);
	appTrapping = 0;
    break;
  case SIGALRM:
    if(appTrapping) break;
    appTrapping = 2;
    if(appTimerHandler) (*appTimerHandler)();
	appTrapping = 0;
    break;
  case SIGSEGV:
  case SIGBUS:
  case SIGFPE:
  case SIGILL:
    if(appTrapping==3) pthread_exit(NULL);
    appTrapping=3;
    tid=pthread_self();
    excode=(*appFatalHandler)(sig, tid, appMainThreadId);
    if(excode) shutdownApplication();
	appTrapping=0;
    break;
  case SIGCLD:
    wait(&excode); break;
  default:
    if(appTrapping) break;
    appTrapping = 4;
    sig2str(sig, signame);
    output(11,"'%s' received signal %s ( %d )\n", AppName, signame, sig);    
	appTrapping = 0;
  }
}

void exitApplication(void);

void InstallAppSignalHandler()
{
sigset_t smask;
int i;
  sigemptyset(&smask);
  appSigAction.sa_handler=NULL;
  appSigAction.sa_sigaction=appSignalHandler;
  appSigAction.sa_mask=smask;
  pthread_sigmask(SIG_SETMASK, &smask, NULL);
  for(i=1;i<=37;i++) { 
    appSigAction.sa_flags= (i==SIGSEGV || i==SIGBUS || i==SIGFPE) ? SA_RESETHAND|SA_RESTART : SA_RESTART;
    sigaction(i, &appSigAction, NULL);
  }
}

int  StartApplication()
{
int pid;
char filename[100];
FILE *fp;
  appRunning=0;
  if(RunMode) {
    if((pid=fork())) exit(0);
    setsid();
    if((pid=fork())) exit(0);
    umask(0);
  }
  pid=getpid();
  sprintf(filename,"%s/.%s", _WORKDIR, AppName);
  fp=fopen(filename, "wt");
  if(!fp) return -1;
  atexit(exitApplication);
  fprintf(fp,"%d", pid);
  fclose(fp);
  appMainThreadId = pthread_self();
  chmod(filename, 0660);
  InstallAppSignalHandler();
  SetAppFatalHandler(defaultFatalHandler);
  appRunning=1;
  appStartTime = time(NULL);
  return pid;
}

static int _checkAppName(char *prog, char *argv[], char *appname)
{
int i,named;
char *arg, *p;
  for(i=1,named=0;(arg=argv[i]);i++) {
    if(strncmp(arg, "-n", 2)) continue;
    if(!strcmp(arg+2, appname)) return 1;
    if(arg[2]=='\0') if(argv[i+1]) if(!strcmp(argv[i+1], appname)) return 1;
    named=1; break;
  }
  p = strrchr(argv[0], '/');
  if(p) p++; else p=argv[0];
  if(!strcmp(p, appname)) return named ? 2 : 1;
  if(prog==argv[0]) return 0;
  p = strrchr(prog, '/');
  if(p) p++; else p=prog;
  if(!strcmp(p, appname)) return named ? 3 : 2;
  return 0;
}

static int _checkAppPid(int pid, char *appname)
{
#ifdef __linux__
struct stat fs;
#else
psinfo_t ps;
#endif
int fd, ret, i;
char fname[512+1];
char *p;
char *argv[16+1];
uid_t myuid;
  if(pid==getpid()) return 0;
  if(pid==getppid()) return 0;
  if(kill(pid, 0)<0) return -1;
  myuid = geteuid();
#ifdef __linux__
  sprintf(fname, "/proc/%d/cmdline", pid);
  fd = open(fname, 0);
  if(fd==-1) return -1;
  if(fstat(fd, &fs)<0) { close(fd); return -1; }
  if(fs.st_uid != myuid) { close(fd); return 0; }
  ret = read(fd, fname, 512);
  close(fd);
  if(ret<=0) return -1;
  fname[ret] = '\0';
  argv[0] = fname;
  for(i=0,p=fname;*p;p+=strlen(p)+1) {
    if(i<16) argv[i++] = p;
  }
  argv[i] = NULL;
  if(i==0) return -1;
  return _checkAppName(fname, argv, appname);
#else
  sprintf(fname, "/proc/%d/psinfo", pid);
  fd = open(fname, 0);
  if(fd==-1) return -1;
  ret=read(fd, &ps, sizeof(ps));
  close(fd);
  if(ret<sizeof(ps)) return -1;
  if(ps.pr_euid != myuid) return 0;
  argv[0] = ps.pr_psargs;
  for(i=1,p=ps.pr_psargs;*p;p++) if(*p==' ') {
    *p++ = '\0';
    if(i<16) argv[i++] = p;
  }
  argv[i] = NULL;
  return _checkAppName(ps.pr_fname, argv, appname);
#endif
}

int  _getAppPid(char *appname)
{
DIR *dir;
struct dirent *dp;
int ret,pid;
int rret, rpid;
  dir = opendir("/proc");
  if(!dir) return -1;
  rret = rpid = -1;
  while((dp=readdir(dir))) {
    pid = atoi(dp->d_name);
    if(pid <= 0) continue;
    ret = _checkAppPid(pid, appname);
    if(ret <= 0) continue;
    if(ret == 1) { rpid = pid; break; }
    if(rpid != -1 && ret >= rret) continue;
    rpid = pid; rret = ret;
  }
  closedir(dir);
  return rpid;
}

int  getAppPid(char *appname)
{
char filename[100];
int pid;
FILE *fp;
  sprintf(filename,"%s/.%s", _WORKDIR, appname);
  fp=fopen(filename, "rt");
  if(!fp) return _getAppPid(appname);
  fscanf(fp,"%d", &pid);
  fclose(fp);
  if(_checkAppPid(pid, appname)>0) return pid;
  return _getAppPid(appname);
}

int  StopApplication(char *appname, int timeout)
{
//char filename[100];
int pid;
  pid=getAppPid(appname);
  if(pid==-1) return -1;
  kill(pid, SIGTERM);
  if(timeout<0) return 1;
  for(;timeout>0;timeout--) if(kill(pid,0)==-1) break; else sleep(1);
  if(!timeout) kill(pid, SIGKILL);
  if(kill(pid, 0)==0) return -1;
  if(errno == EPERM) return -1;
//  the following lines are removed on 2007.9.29 by hewton, to prevent the pid file belonging to a new instance with the same name(restared automatically by scheduler) been removed unexpectedly
//  sprintf(filename,"%s/.%s", _WORKDIR, appname); 
//  unlink(filename);  
  return 1;
}

void exitApplication()
{
char filename[100];
  sprintf(filename,"%s/.%s", _WORKDIR, AppName);
  unlink(filename);
}

int  CheckApplication(char *appname)
{
  return getAppPid(appname);
}

int SendAppCommand5(char *appname, int cmd, char *para, char *device)
{
struct shmctl_t *ctl;
int pid,i,offset,ret;
int shmid;
char *p, *shmaddr;
char path[300+1];
FILE *fp;
  pid=getAppPid(appname);
  if(pid==-1) return -1;
  shmid=shmget(pid, 1048576, 0660|IPC_CREAT|IPC_EXCL);
  if(shmid==-1) if((shmid=shmget(pid, 0, 0660))==-1) return 0;
  shmaddr=(char *)shmat(shmid, NULL, 0660);
  if(!shmaddr) { shmctl(shmid, IPC_RMID, NULL); return 0; }
  shmaddr[1]=cmd;
  if(!device) fp = stdout; else fp = fopen(device, "w");
  if(!fp) fp = stdout;
  if(!device) { device = ttyname(0); if(!device) device = ""; }
  else if(*device!='/') {
    getcwd(path, 200);
    strcat(path, "/");
    strcat(path, device);
    device = path;
  }
  p = shmaddr+2;
  strcpy(p, device);
  p += strlen(p) + 1;
  if(para) strcpy(p, para); else *p='\0';
  p += strlen(p) + 1;
  *p = '\0';
  p = shmaddr + 1024;
  ctl = (struct shmctl_t *)p;
//  ctl->ident = (int)ctl;
  ctl->start = offset = sizeof(struct shmctl_t);
  ctl->limit = 1048576 - 1024 - offset;
  *shmaddr='0';
  kill(pid, SIGINT);
  for(i=0;i<100;i++) {
    if(kill(pid,0)) break;
    ret = ctl->start - offset;
    if(ret>0) { fwrite(p + offset, 1,  ret, fp); offset += ret;  }
    if(*shmaddr=='0') { poll(NULL,0,100); continue; }
    if(*shmaddr=='1') break; else *shmaddr = '0';
  }
  ret = ctl->start - offset;
  if(ret>0) fwrite(p + offset, 1,  ret, fp); 
  shmdt(shmaddr);
  shmctl(shmid, IPC_RMID, NULL);
  if(fp == stdout) fflush(fp); else fclose(fp);
  if(i==100) return 0;
  return 1;
}

int SendAppCommand4(char *appname, int cmd, char *para, char *device)
{
int pid,i;
int shmid;
char *p, *shmaddr;
char path[300+1];
  pid=getAppPid(appname);
  if(pid==-1) return -1;
  shmid=shmget(pid, SHMLBA, 0660|IPC_CREAT|IPC_EXCL);
  if(shmid==-1) if((shmid=shmget(pid, 0, 0660))==-1) return 0;
  shmaddr=(char *)shmat(shmid, NULL, 0660);
  if(!shmaddr) { shmctl(shmid, IPC_RMID, NULL); return 0; }
  shmaddr[1]=cmd;
  if(!device) { device = ttyname(0); if(!device) device = ""; }
  else if(*device!='/') {
    getcwd(path, 200);
    strcat(path, "/");
    strcat(path, device);
    device = path;
  }
  p = shmaddr+2;
  strcpy(p, device);
  p += strlen(p) + 1;
  if(para) strcpy(p, para); else *p='\0';
  p += strlen(p) + 1;
  *p = '\0';
  *shmaddr='0';
  kill(pid, SIGINT);
  for(i=0;i<100;i++) {
    if(kill(pid,0)) break;
    if(*shmaddr=='0') { poll(NULL,0,100); continue; }
    if(*shmaddr=='1') break; else *shmaddr = '0';
  }
  shmdt(shmaddr);
  shmctl(shmid, IPC_RMID, NULL);
  if(i==100) return 0;
  return 1;
}

int SendAppCommand(char *appname, int cmd, char *para)
{
  return SendAppCommand4(appname, cmd, para, NULL);
}

int  HookAppOutput(char *appname, char *filename)
{
  return SendAppCommand4(appname, -1, NULL, filename);
}

int  SetAppCommandHandler(dchandler_t handler)
{
  appCommandHandler=handler; return 1;
}

int  SetAppCommandHandler4(dchandler_t4 handler)
{
  appCommandHandler4=handler; 
  appCommandHandler5=handler; 
  appCommandHandler6=handler; return 1;
}

int  SetAppCommandHandler5(dchandler_t4 handler)
{
  appCommandHandler5=handler;
  appCommandHandler6=handler; return 1;
}

int  SetAppCommandHandler6(dchandler_t4 handler)
{
  appCommandHandler6=handler; return 1;
}

int  SetAppFatalHandler(fthandler_t handler)
{
  appFatalHandler=handler; return 1;
}

int SetAppTimerHandler(void (*handler)())
{
  appTimerHandler=handler; return 1;
}

int  SetAppOutputLevel4(char *appname, char *level)
{
  return SendAppCommand(appname, -2, level);
}

int  SetAppOutputLevel(char *appname, int level)
{
char s[20];
  sprintf(s, "%d-", level);
  return SendAppCommand(appname, -2, s);
}

void ShowApplicationUsage(char *usage)
{
char *appname = AppName;
    if(!usage) usage="";
    printf("Show usage of %s : %s -h\n", appname, appname);
    printf("Start %s : ", appname);
    printf("%s [-n <name>] [-bg] [-o <device>] [-l <level>] [-B <branch>] %s\n", appname, usage);
    printf("Stop %s : ", appname);
    printf("%s [-n <name>] -x [<timeout>]\n",appname);
    printf("Send console command to %s : ", appname);
    printf("%s [-n <name>] -c [<command> [<param>]]\n", appname);
    printf("Redirect output of %s to file : ", appname);
    printf("%s [-n <name>] -o [<device>]\n", appname);
    printf("Change the output level of %s : ", appname);
    printf("%s [-n <name>] -l [<level>]\n", appname);
}

void ShowApplicationVersion()
{
    printf("WTF-%s Version %d.%02x.%04x, Copyright 2000-2007, WellTelecom Co. Ltd.\n",
  AppName, (appVersion>>24)&0x0ff, (appVersion>>16)&0x0ff, appVersion&0x0ffff);
}

void gohome(char *filename)
{
char *path, *p;
char dir[300];
int n;
struct stat fs;
  p = strrchr(filename, '/');
  if(p) { n=p-filename; strncpy(dir, filename, n); dir[n]='\0'; chdir(dir); return ; }
  if(!stat(filename, &fs)) if(fs.st_mode&S_IFREG) return;
  path = getenv("PATH");
  if(!path) return;
  while((p=strchr(path, ':'))) {
    n = p - path;
    strncpy(dir, path, n);
    sprintf(dir+n, "/%s", filename);
    if(!stat(dir, &fs)) if(fs.st_mode&S_IFREG) { dir[n]='\0'; chdir(dir); return; }
    path = p + 1;
  }
  sprintf(dir, "%s/%s", path, filename);
  if(!stat(dir, &fs)) if(fs.st_mode&S_IFREG) chdir(path);
}

int RunApplication(int argc, char *argv[], char *usage)
{
char *p, *device=NULL, *param=NULL, *level=NULL;
int i, cmd, n;
int optoutfile=0, optlevel=0;
char *appname;
  OutFile = stdout;
  p = getenv("TCP_CACHE_SIZE");
  if(p) TCPCacheSize = atoi(p);
  p = getenv("TCP_NODELAY");
  if(p) TCPInstant = atoi(p);
  tzset();
  _timezone = timezone;
  p=strrchr(argv[0], '/');
  if(!p) appname=argv[0]; else appname=p+1;
  strcpy(AppName, appname);
  for(i=1, cmd=n=0;i<argc;i++) {
    p=argv[i];
    if(!strncmp(p,"-o", 2)) {
      if(p[2]) device=p+2;
      else if(i+1<argc) { if(argv[i+1][0]!='-') device=argv[++i]; else device=NULL; }
      else device=NULL;
      optoutfile=1;
    }
    else if(!strncmp(p,"-l", 2)) {
      if(p[2]) level=p+2;
      else if(i+1<argc) { if(argv[i+1][0]!='-') level=argv[++i]; else level=NULL; }
      else level=NULL;
      optlevel=1;
    }
    else if(!strncmp(p, "-n", 2)) {
      if(p[2]) p+=2; 
      else if(i+1<argc) { if(argv[i+1][0]!='-') p=argv[++i]; else p=NULL; }
      else p=NULL;
      if(p) strcpy(AppName, p);
    }
    else if(!strncmp(p, "-B", 2)) {
      if(p[2]) appBranch = atoi(p+2);
      else if(i+1<argc) { if(argv[i+1][0]!='-') appBranch=atoi(argv[++i]); }
    }
    else if(!strcmp(p, "-bg"))
      RunMode=1;
    else if(!strcmp(p, "-fg"))
      RunMode=0;
    else if(!strncmp(p, "-c", 2)) {
      cmd=1;
      if(p[2]) n=atoi(p+2); else n=0;
      if(i+1<argc) { if(strncmp(argv[i+1],"-o",2)) param=argv[++i]; else param=NULL; }
      else param=NULL;
    }
    else if(!strncmp(p, "-x", 2)) {
      cmd=2;
      if(p[2]) n=atoi(p+2);
      else if(i+1<argc) { if(argv[i+1][0]!='-') n=atoi(argv[++i]); else n=60; }
      else n=60;
    }
    else if(!strcmp(p, "-h") || !strcmp(p, "-help") || !strcmp(p, "-usage")) {
      ShowApplicationUsage(usage); exit(0);
    }
    else if(!strcmp(p, "-v") || !strcmp(p, "-version")) {
      ShowApplicationVersion(); exit(0);
    }
    else break;
  }
  if(cmd==2) {
    i=StopApplication(AppName, n);
    if(i<0) printf("%s is not running!\n", AppName);
    exit(0);
  }
  if(cmd==1) {
    i=SendAppCommand5(AppName, n, param, device);
    if(i<0) printf("%s is not running!\n", AppName);
    exit(0);
  }
  if(i>=argc) {
    n=0;
    if(optoutfile)  n=HookAppOutput(AppName, device);
    if(optlevel)  n=SetAppOutputLevel4(AppName, level);
    if(n>0) exit(0);
  }
  if(InstanceCheck) if(CheckApplication(AppName)!=-1) {
    printf("'%s' has already been started! Use '%s -n %s -x' to stop it first!\n", 
      AppName, appname, AppName);
    exit(0);
  }
  if(optoutfile) RedirectOutput(device);
  if(optlevel) SetOutputLevel(level);
  gohome(argv[0]);
  return i;
}
