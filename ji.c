/* Copyright 2010 Ramil Farkhshatov

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>. */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>

#include <polarssl/ssl.h>
#include <polarssl/havege.h>

#include <libxmpps/pool.h>
#include <libxmpps/node.h>
#include <libxmpps/xml.h>
#include <libxmpps/xmpp.h>
#include <libxmpps/tls.h>

#include "config.h"

static char *x_roster = "<iq type='get' id='roster'>"
                        "<query xmlns='jabber:iq:roster'/></iq>";

struct contact;

static void cmd_join(struct xmpp *, struct contact *, char *);
static void cmd_join_room(struct xmpp *, struct contact *, char *);
static void cmd_leave(struct xmpp *, struct contact *, char *);
static void cmd_away(struct xmpp *, struct contact *, char *);
static void cmd_roster(struct xmpp *, struct contact *, char *);
static void cmd_who(struct xmpp *, struct contact *, char *);

struct command {
  char c;
  void (*fn)(struct xmpp *, struct contact *, char *);
} commands[] = {
  {'j', cmd_join},
  {'g', cmd_join_room},
  {'l', cmd_leave},
  {'a', cmd_away},
  {'r', cmd_roster},
  {'w', cmd_who},
  {0, 0}
};

struct contact {
  int fd;
  char jid[JID_BUF];
  char show[STATUS_BUF];
  char status[STATUS_BUF];
  char *type;
  struct contact *next;
};

int in_tls = 0;
int is_ready = 0;
int fd = -1;
struct tls tls;
struct contact *contacts = 0;
char rootdir[PATH_BUF] = "";
char me[JID_BUF] = "";

static int open_pipe(const char *name);
static void send_status(struct xmpp *x, const char *status, const char *msg);
static void send_message(struct xmpp *x, const char *type, const char *to,
                         const char *msg);

#define find_contact(v, ns, s) \
  for (v = contacts; v && (strncmp(v->jid, (s), (ns)) || u->jid[(ns)]); \
       v = v->next);

static void
log_printf(int level, const char *fmt, ...)
{
  va_list args;

  if (level <= log_level) {
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
  }
}

int
tcp_connect(char *host, int port)
{
  struct sockaddr_in srv_addr;
  struct hostent *srv_host;
  int fd;

  srv_host = gethostbyname(host);
  if (!srv_host || sizeof(srv_addr.sin_addr) < srv_host->h_length)
    return -1;
  fd = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
  if (fd < 0)
    return -1;
  memcpy(&srv_addr.sin_addr, srv_host->h_addr, srv_host->h_length);
  srv_addr.sin_family = AF_INET;
  srv_addr.sin_port = htons(port);
  if (connect(fd, (struct sockaddr *)&srv_addr, sizeof(srv_addr)) < 0) {
    close(fd);
    return -1;
  }
  return fd;
}

static int
tcp_recv(int bytes, char *buf, void *user)
{
  int n;
  do {
    n = recv(fd, buf, bytes, 0);
  } while (n < 0 && errno == EAGAIN);
  log_printf(20, "tcp_recv [%d/%d]\n", n, bytes);
  if (bytes > 0 && !n)
    return -1;
  return n;
}

static int
tcp_send(int bytes, const char *buf, void *user)
{
  int w, n;
  n = 0;
  while (n < bytes) {
    w = send(fd, buf + n, bytes - n, 0);
    if (w < 0)
      return -1;
    n += w;
  }
  log_printf(20, "tcp_send [%d/%d]\n", n, bytes);
  return n;
}

static int
io_recv(int bytes, char *buf, int *remain, void *user)
{
  int n;
  *remain = 0;
  n = (in_tls)
      ? tls_recv(bytes, buf, remain, &tls) : tcp_recv(bytes, buf, user);
  if (n > 0)
    log_printf(10, "\n<- %c[%d] '%.*s'\n\n", (in_tls) ? '&' : ' ', n, n, buf);
  return n;
}

static int
io_send(int bytes, const char *buf, void *user)
{
  int i;
  if (log_level >= 10)
    for (i = 0; i < bytes; i++)
      if (!isspace(buf[i])) {
        log_printf(10, "\n-> %c[%d] %.*s\n\n", (in_tls) ? '&' : ' ', bytes,
                   bytes, buf);
        break;
      }
  return (in_tls) ? tls_send(bytes, buf, &tls) : tcp_send(bytes, buf, user);
}

static struct contact *
add_contact(int njid, const char *jid)
{
  struct contact *u;

  find_contact(u, njid, jid);
  if (u)
    return u;

  u = calloc(1, sizeof(struct contact));
  if (!u)
    return 0;

  snprintf(u->jid, sizeof(u->jid), "%.*s", njid, jid);
  u->fd = open_pipe(u->jid);
  u->next = contacts;
  u->type = "chat";
  snprintf(u->show, sizeof(u->show), "%s", STR_OFFLINE);
  u->status[0] = 0;
  contacts = u;

  return u;
}

static void
rm_contact(struct contact *c)
{
  char infile[PATH_BUF];
  struct contact *p;

  if (c == contacts)
    contacts = contacts->next;
  else {
    for (p = contacts; p && p->next != c; p = p->next) {}
    if (p && p->next == c)
      p->next = c->next;
  }

  if (c->fd >= 0) {
    snprintf(infile, sizeof(infile), "%s/%s/in", rootdir, c->jid);
    remove(infile);
    close(c->fd);
  }
  free(c);
}

static int
read_line(int fd, size_t len, char *buf)
{
  char c = 0;
  size_t i = 0;

  do {
    if (read(fd, &c, sizeof(char)) != sizeof(char))
      return -1;
    buf[i++] = c;
  } while (c != '\n' && i < len);
  buf[i - 1] = 0;
  return 0;
}

static void
mkdir_rec(const char *dir)
{
  char tmp[PATH_BUF];
  char *p = 0;
  size_t len;

  snprintf(tmp, sizeof(tmp), "%s", dir);
  len = strlen(tmp);
  if (tmp[len - 1] == '/')
    tmp[len - 1] = 0;
  for (p = tmp + 1; *p; p++)
    if (*p == '/') {
      *p = 0;
      mkdir(tmp, S_IRWXU);
      *p = '/';
    }
  mkdir(tmp, S_IRWXU);
}

static int
open_pipe(const char *name)
{
  char path[PATH_BUF];

  snprintf(path, sizeof(path), "%s/%s", rootdir, name);
  if (access(path, F_OK) == -1)
    mkdir_rec(path);
  snprintf(path, sizeof(path), "%s/%s/in", rootdir, name);
  if (access(path, F_OK) == -1)
    mkfifo(path, S_IRWXU);
  return open(path, O_RDONLY | O_NONBLOCK, 0);
}

static void
print_msg(int len, const char *from, const char *fmt, ...)
{
  va_list args;
  char path[PATH_BUF], date[128];
  time_t t;
  FILE *f;

  if (!len)
    len = strlen(from);

  snprintf(path, sizeof(path), "%s/%.*s", rootdir, len, from);
  mkdir_rec(path);
  snprintf(path, sizeof(path), "%s/%.*s/out", rootdir, len, from);
  f = fopen(path, "a");
  if (f) {
    t = time(0);
    strftime(date, sizeof(date), "%Y-%m-%d %H:%M", localtime(&t));
    fprintf(f, "%s ", date);
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);
    fclose(f);
  }
}

static void
send_status(struct xmpp *x, const char *status, const char *msg)
{
  const char *p = "<presence><show>%s</show><status>%s</status></presence>";
  xmpp_printf(x, p, status, msg);
}

static void
send_message(struct xmpp *x, const char *type, const char *to,
             const char *msg)
{
  const char *m = "<message to='%s' type='%s'><body>%s</body></message>";
  xmpp_printf(x, m, to, type, msg);
}

static void
join_room(struct xmpp *xmpp, const char *to)
{
  static const char *muc_ns = "http://jabber.org/protocol/muc";
  static const char *p = "<presence to='%s'><x xmlns='%s'/></presence>";
  xmpp_printf(xmpp, p, to, muc_ns);
}

static void
request_presence(struct xmpp *xmpp, const char *to)
{
  xmpp_printf(xmpp, "<presence type='probe' to='%s'/>", to);
}

static int
msg_hook(int x, struct xmpp *xmpp)
{
  char *s, *from, *part, *n, *type;
  int npart, len;
  struct contact *u;

  s = xml_node_find_text(x, "body", &xmpp->xml.mem);
  from = xml_node_find_attr(x, "from", &xmpp->xml.mem);
  part = from ? jid_partial(from, &npart) : 0;
  if (!part || !s)
    return 0;
  u = add_contact(npart, part);
  type = xml_node_find_attr(x, "type", &xmpp->xml.mem);
  if (type && !strcmp(type, "groupchat")) {
    u->type = "groupchat";
    n = jid_resource(from, &len);
  } else
    n = jid_name(from, &len);
  print_msg(npart, from, "<%.*s> %s\n", len, n, s);
  return 0;
}

static int
presence_hook(int x, struct xmpp *xmpp)
{
  char *show, *s, *status, *from, *part, *type;
  struct contact *u;
  int npart;

  show = xml_node_find_text(x, "show", &xmpp->xml.mem);
  status = xml_node_find_text(x, "status", &xmpp->xml.mem);
  type = xml_node_find_attr(x, "type", &xmpp->xml.mem);
  from = xml_node_find_attr(x, "from", &xmpp->xml.mem);
  if (!from)
    return 0;

  show = (!show && type && !strcmp("unavailable", type)) ? type : show;
  show = show ? show : STR_ONLINE;
  status = status ? status : "";

  for (s = status; *s; ++s)
    if (*s == '\n')
      *s = '\\';

  part = jid_partial(from, &npart);
  find_contact(u, npart, part);
  if (type && type[0] && (!u || strcmp(u->type, "groupchat")))
    print_msg(0, "", "-!- %s sends %s\n", from, type);
  if (!u || strcmp(u->type, "groupchat"))
    print_msg(0, "", "-!- %s is %s (%s)\n", from, show, status);
  if (u) {
    if (!strcmp(u->type, "groupchat")) {
      if (!strcasecmp(show, STR_ONLINE) || !strcasecmp(show, STR_OFFLINE))
        print_msg(npart, part, "-!- %s is %s\n", from, show);
    } else {
      print_msg(npart, part, "-!- %s is %s (%s)\n", from, show, status);
      snprintf(u->show, sizeof(u->show), "%s", show);
      snprintf(u->status, sizeof(u->status), "%s", status);
    }
  }
  return 0;
}

static int
roster_hook(int x, struct xmpp *xmpp)
{
  struct xml_data *d;
  char *jid, *name, *sub;

  for (d = xml_node_data(xml_node_find(x, "query", &xmpp->xml.mem),
                         &xmpp->xml.mem);
       d; d = xml_data_next(d, &xmpp->xml.mem)) {
    if (d->type != XML_NODE)
      continue;
    jid = xml_node_find_attr(d->value, "jid", &xmpp->xml.mem);
    name = xml_node_find_attr(d->value, "name", &xmpp->xml.mem);
    sub = xml_node_find_attr(d->value, "subscription", &xmpp->xml.mem);
    print_msg(0, "", "* %s - %s - [%s]\n", name ? name : "", jid, sub);
  }
  print_msg(0, "", "End of /R list.\n");
  for (d = xml_node_data(xml_node_find(x, "query", &xmpp->xml.mem),
                         &xmpp->xml.mem);
       d; d = xml_data_next(d, &xmpp->xml.mem)) {
    if (d->type != XML_NODE)
      continue;
    jid = xml_node_find_attr(d->value, "jid", &xmpp->xml.mem);
    request_presence(xmpp, jid);
  }
  return 0;
}

static void
cmd_join(struct xmpp *xmpp, struct contact *u, char *s)
{
  char *p, *part;
  int len;

  p = strchr(s + 3, ' ');
  if (p)
    *p = 0;
  part = jid_partial(s + 3, &len);
  if (!part)
    return;
  add_contact(len, part);
  if (p) {
    send_message(xmpp, "chat", s + 3, p + 1);
    print_msg(len, part, "<%s> %s\n", me, p + 1);
  }
}

static void
cmd_join_room(struct xmpp *xmpp, struct contact *u, char *s)
{
  char *p, *part, *res;
  char to[JID_BUF];
  int npart, nres;

  p = strchr(s + 3, ' ');
  if (p)
    *p = 0;
  part = jid_partial(s + 3, &npart);
  res = jid_resource(s + 3, &nres);
  if (!(part && res))
    return;
  u = add_contact(npart, part);
  u->type = "groupchat";
  snprintf(to, sizeof(to), "%.*s/%.*s", npart, part, nres, res);
  join_room(xmpp, to);
}

static void
cmd_leave(struct xmpp *xmpp, struct contact *u, char *s)
{
  char *part;
  int len;

  if (s[2] && s[3]) {
    part = jid_partial(s + 3, &len);
    if (!part)
      return;
    find_contact(u, len, part);
  }
  if (!u->jid[0])
    return;
  if (!strcmp(u->type, "groupchat"))
    xmpp_printf(xmpp, "<presence to='%s' type='unavailable'/>", u->jid);
  rm_contact(u);
}

static void
cmd_away(struct xmpp *xmpp, struct contact *u, char *s)
{
  me_status = !me_status;
  if (s[2])
    snprintf(stats[me_status].msg, sizeof(stats[me_status].msg), "%s", s + 3);
  send_status(xmpp, stats[me_status].show, stats[me_status].msg);
}

static void
cmd_roster(struct xmpp *xmpp, struct contact *u, char *s)
{
  xmpp_printf(xmpp, x_roster);
}

static void
cmd_who(struct xmpp *xmpp, struct contact *u, char *s)
{
  if (s[2] && s[3])
    request_presence(xmpp, s + 3);
  else if (u->jid[0])
    request_presence(xmpp, u->jid);
}

static void
do_contact_input_string(struct xmpp *xmpp, struct contact *u, char *s)
{
  struct command *cmd;

  if (s[0] == 0)
    return;

  if (s[0] != '/') {
    if (u->jid[0])
      send_message(xmpp, u->type, u->jid, s);
    else
      xmpp_printf(xmpp, "%S", s);
    if (strcmp(u->type, "groupchat"))
      print_msg(0, u->jid, "<%s> %s\n", me, s);
    return;
  }
  for (cmd = commands; cmd->c; ++cmd)
    if (cmd->c == s[1] && cmd->fn != 0) {
      cmd->fn(xmpp, u, s);
      break;
    }
  if (!cmd->c) {
    send_message(xmpp, u->type, u->jid, s);
    if (strcmp(u->type, "groupchat"))
      print_msg(0, u->jid, "<%s> %s\n", me, s);
  }
}

static void
handle_contact_input(struct xmpp *xmpp, struct contact *u)
{
  static char buf[PIPE_BUF];

  if (read_line(u->fd, sizeof(buf), buf) == -1) {
    close(u->fd);
    u->fd = open_pipe(u->jid);
    if (u->fd < 0)
      rm_contact(u);
  } else
    do_contact_input_string(xmpp, u, buf);
}

static int
start_tls(void *user)
{
  if (!in_tls && use_tls) {
    memset(&tls, 0, sizeof(tls));
    tls.recv = tcp_recv;
    tls.send = tcp_send;
    if (tls_start(&tls))
      return -1;
    in_tls = 1;
  }
  return 0;
}

static int
auth_handler(int x, void *user)
{
  struct xmpp *xmpp = (struct xmpp *)user;
  int n;
  char *name;

  send_status(xmpp, stats[me_status].show, stats[me_status].msg);
  xmpp_printf(xmpp, x_roster);
  name = jid_name(xmpp->jid, &n);
  if (name)
    snprintf(me, sizeof(me), "%.*s", n, name);
  is_ready = 1;
  return 0;
}

static int
stream_handler(int x, void *user)
{
  struct xmpp *xmpp = (struct xmpp *)user;
  if (!in_tls && use_tls)
    if (xmpp_starttls(xmpp))
      return -1;
  return 0;
}

static int
node_handler(int x, void *user)
{
  struct xmpp *xmpp = (struct xmpp *)user;
  int r;
  char *name;

  r = xmpp_default_node_hook(x, xmpp, user);
  if (r < 0)
    return -1;
  if (r)
    return 0;
  name = xml_node_name(x, &xmpp->xml.mem);
  if (!name)
    return -1;
  if (!strcmp(name, "message"))
    return msg_hook(x, xmpp);
  if (!strcmp(name, "presence"))
    return presence_hook(x, xmpp);
  if (!strcmp(name, "iq")) {
    name = xml_node_find_attr(x, "id", &xmpp->xml.mem);
    if (name && !strcmp(name, "roster"))
      return roster_hook(x, xmpp);
  }
  return 0;
}

static int
process_server_input(int fd, struct xmpp *xmpp)
{
  char buf[DATA_BUF];
  int n, remain;

  do {
    n = io_recv(sizeof(buf), buf, &remain, &fd);
    if (n < 0) {
      print_msg(0, "", "; error: reading from socket (remain: %d)\n", remain);
      return -1;
    }
    log_printf(20, "; processing state: '%d' buf: '%.*s'\n", xmpp->xml.state,
               n, buf);
    if (xmpp_process_input(n, buf, xmpp, xmpp)) {
      print_msg(0, "", "; error: processing xmpp xml\n");
      log_printf(20, "; state: '%d' buf: '%.*s'\n", xmpp->xml.state, n, buf);
      return -1;
    }
  } while (remain > 0);
  return 0;
}

static int
process_connection(int fd, struct xmpp *xmpp)
{
  int res, max_fd;
  struct contact *u, *next;
  fd_set fds;
  time_t last_response;
  struct timeval tv;

  add_contact(0, "");
  last_response = time(0);
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
  while (1) {
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    max_fd = fd;
    for (u = contacts; u && is_ready; u = u->next)
      if (u->fd >= 0) {
        FD_SET(u->fd, &fds);
        if (u->fd > max_fd)
          max_fd = u->fd;
      }
    tv.tv_sec = keep_alive_ms / 1000;
    tv.tv_usec = (keep_alive_ms % 1000) * 1000;
    res = select(max_fd + 1, &fds, 0, 0, (keep_alive_ms > 0) ? &tv : 0);
    if (res < 0)
      break;
    if (res > 0) {
      if (FD_ISSET(fd, &fds) && process_server_input(fd, xmpp))
        break;
      for (u = contacts; u; u = next) {
        next = u->next;
        if (FD_ISSET(u->fd, &fds))
          handle_contact_input(xmpp, u);
      }
    } else if (io_send(1, " ", &fd) < 1)
      break;
  }
  return 0;
}

static void
die_usage(void)
{
  fprintf(stderr, "%s",
    "ji - jabber it - " VERSION "\n"
    "(C)opyright 2010-2011 Ramil Farkhshatov\n"
    "usage: ji [-r dir] [-j jid] [-s server] [-n nick] [-p port]\n");
  exit(1);
}

int
main(int argc, char **argv)
{
  struct xmpp xmpp = {0};
  char path_buf[PATH_BUF];
  int i, port = XMPP_PORT, ret = 1;
  char *jid = 0, *srv = 0, *s;

  s = getenv("HOME");
  snprintf(path_buf, sizeof(path_buf), "%s/%s", (s) ? s : ".", root);
  s = getenv("USER");
  snprintf(me, sizeof(me), "%s", (s) ? s : "me");

  for (i = 1; i < argc - 1 && argv[i][0] == '-'; i++)
    switch (argv[i][1]) {
    case 'r': snprintf(path_buf, sizeof(path_buf), "%s", argv[++i]); break;
    case 'n': snprintf(me, sizeof(me), "%s", argv[++i]); break;
    case 'j': jid = argv[++i]; break;
    case 's': srv = argv[++i]; break;
    case 'p': port = atoi(argv[++i]); break;
    case 'l': log_level = atoi(argv[++i]); break;
    default: die_usage();
    }
  if (!jid)
    die_usage();

  xmpp.send = io_send;
  xmpp.tls_fn = start_tls;
  xmpp.stream_fn = stream_handler;
  xmpp.node_fn = node_handler;
  xmpp.auth_fn = auth_handler;
  xmpp.use_sasl = use_sasl;
  xmpp.jid = jid;

  if (read_line(0, sizeof(xmpp.pwd), xmpp.pwd))
    xmpp.pwd[0] = 0;

  if (xmpp_init(&xmpp, 4096))
    return 1;

  if (!srv)
    srv = xmpp.server;

  s = jid_partial(xmpp.jid, &i);
  snprintf(rootdir, sizeof(rootdir), "%s/%.*s", path_buf, i, s);

  fd = tcp_connect(srv, port);
  if (fd < 0)
    return 1;

  if (!(xmpp_start(&xmpp) != 0 || process_connection(fd, &xmpp)))
    ret = 0;

  xmpp_clean(&xmpp);
  close(fd);
  shutdown(fd, 2);
  return ret;
}
