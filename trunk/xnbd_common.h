#ifndef XNBD_COMMON_H
#define XNBD_COMMON_H

#define DEFAULT_XNBDSERVER_LOGFILE "/tmp/xnbd.log"

void redirect_stderr(const char *logfile);
void detach(const char *logpath);

#endif
