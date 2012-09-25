#ifndef XNBD_COMMON_H
#define XNBD_COMMON_H

#define DEFAULT_XNBDSERVER_LOGFILE "/tmp/xnbd.log"

void redirect_stderr(const char *logfile);
int get_log_fd(const char *path);
void detach(const char *logpath);

#endif
