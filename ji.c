#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <iksemel.h>

int keep_alive_ms = 120;
int log_level = 10;
int me_status = 0;
int use_tls = 0;
int use_sasl = 1;
int use_plain = 0;
int is_log_xml = 0;

#define VERSION "0.1"
#define DEFAULT_RESOURCE "CCCP"
#define STR_ONLINE "Online"
#define STR_OFFLINE "Offline"
#define PING_TIMEOUT 300
#define JID_BUF 256
#define PW_BUF 256
#define PIPE_BUF 4096
#define PATH_BUF 512
#define STATUS_BUF 256

struct status {
  enum ikshowtype show;
  char msg[STATUS_BUF];
} statuses[] = {
  {IKS_SHOW_AVAILABLE, "Here I am."},
  {IKS_SHOW_AWAY, "Away."},
};

struct context;
struct contact;

static void cmd_join(struct context *, struct contact *, char *);
static void cmd_join_room(struct context *, struct contact *, char *);
static void cmd_leave(struct context *, struct contact *, char *);
static void cmd_away(struct context *, struct contact *, char *);
static void cmd_roster(struct context *, struct contact *, char *);
static void cmd_who(struct context *, struct contact *, char *);

struct command {
  char c;
  void (*fn)(struct context *, struct contact *, char *);
} commands[] = {
  {'j', cmd_join},
  {'g', cmd_join_room},
  {'l', cmd_leave},
  {'a', cmd_away},
  {'r', cmd_roster},
  {'w', cmd_who},
  {0}
};

struct contact {
  int fd;

  char jid[JID_BUF];
  char show[STATUS_BUF];
  char status[STATUS_BUF];
  enum iksubtype type;

  struct contact *next;
};

struct context {
  char *password;
  iksparser *parser;
  iksid *account;
  iksfilter *filter;

  int is_authorized;
};

struct contact *contacts = 0;
char rootdir[PATH_BUF] = "";
char me[JID_BUF] = "";
int server_fd = -1;

static int stream_start_hook(struct context *s, int type, iks *node);
static int stream_normal_hook(struct context *s, int type, iks *node);
static int stream_stop_hook(struct context *s, int type, iks *node);
static void make_path(int dst_bytes, char *dst, const char *dir,
                      const char *file);
static int open_pipe(const char *name);
static void send_status(struct context *c, enum ikshowtype status,
                        const char *msg);
static void send_message(struct context *c, enum iksubtype type,
                  const char *to, const char *msg);

static size_t
strlcpy(char *dst, const char *src, size_t size)
{
  const char *s = src;
  for (--size; size && *s; --size, ++dst, ++s)
    *dst = *s;
  *dst = 0;
  while(*s++);
  return s - src - 1;
}

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

static void
log_xml(int level, const char *prefix, iks *x)
{
  char *s;

  s = iks_string(0, x);
  log_printf(level, "%s: %s\n", prefix, s);
  iks_free(s);
}

static struct contact *
add_contact(const char *jid)
{
  char infile[PATH_BUF];
  struct contact *u;

  for (u = contacts; u; u = u->next)
    if (!strcmp(jid, u->jid))
      return u;

  make_path(sizeof(infile), infile, jid, "in");
  if (!infile[0])
    return 0;

  u = calloc(1, sizeof(struct contact));
  if (!u)
    return 0;

  strlcpy(u->jid, jid, sizeof(u->jid));
  u->fd = open_pipe(u->jid);
  u->next = contacts;
  u->type = IKS_TYPE_NONE;
  strcpy(u->show, STR_OFFLINE);
  strcpy(u->status, "");
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
    for (p = contacts; p && p->next != c; p = p->next);
    if (p->next == c)
      p->next = c->next;
  }

  if (c->fd >= 0) {
    make_path(sizeof(infile), infile, c->jid, "in");
    if (infile[0])
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

  strlcpy(tmp, dir, sizeof(tmp));
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

static void
make_path(int dst_bytes, char *dst, const char *dir, const char *file)
{
  dst[0] = 0;
  if (dst_bytes > strlen(rootdir) + 1 + strlen(dir) + 1 + strlen(file) + 1)
    sprintf(dst, "%s/%s/%s", rootdir, dir, file);
}

static int
open_pipe(const char *name)
{
  char path[PATH_BUF];

  make_path(sizeof(path), path, name, "");
  if (access(path, F_OK) == -1)
    mkdir_rec(path);
  make_path(sizeof(path), path, name, "in");
  if (!path[0])
    return -1;
  if (access(path, F_OK) == -1)
    mkfifo(path, S_IRWXU);
  return open(path, O_RDONLY | O_NONBLOCK, 0);
}

static void
print_msg(const char *from, const char *fmt, ...)
{
  va_list args;
  char path[PATH_BUF], date[128];
  time_t t;
  FILE *f;

  make_path(sizeof(path), path, from, "");
  if (!path[0])
    return;
  mkdir_rec(path);
  make_path(sizeof(path), path, from, "out");
  if (!path[0])
    return;
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
send_status(struct context *c, enum ikshowtype status, const char *msg)
{
  iks *x;

  x = iks_make_pres(status, msg);
  iks_send(c->parser, x);
  iks_delete(x);
}

static void
send_message(struct context *c, enum iksubtype type, const char *to,
             const char *msg)
{
  iks *x;

  x = iks_make_msg(type, to, msg);
  iks_send(c->parser, x);
  iks_delete(x);
}

static void
join_room(struct context *c, const char *room, const char *nick)
{
  iks *x;
  char to[JID_BUF];
  char *muc_ns = "http://jabber.org/protocol/muc";

  sprintf(to, "%s/%s", room, nick);
  x = iks_new("presence");
  iks_insert_attrib(x, "to", to);
  iks_insert_attrib(iks_insert(x, "x"), "xmlns", muc_ns);
  iks_send(c->parser, x);
  iks_delete(x);
}

static void
request_presence(struct context *c, const char *to)
{
  iks *x;

  x = iks_new("presence");
  iks_insert_attrib(x, "type", "probe");
  iks_insert_attrib(x, "to", to);
  iks_send(c->parser, x);
  iks_delete(x);
}

static int
stream_start_hook(struct context *c, int type, iks *node)
{
  if (use_tls && !iks_is_secure(c->parser)) {
    iks_start_tls(c->parser);
  }
  if (!use_sasl) {
    iks *x;
    char *sid = 0;

    if (!use_plain)
      sid = iks_find_attrib(node, "id");
    x = iks_make_auth(c->account, c->password, sid);
    iks_insert_attrib(x, "id", "auth");
    iks_send(c->parser, x);
    iks_delete(x);
  }
  return IKS_OK;
}

static int
stream_normal_hook(struct context *c, int type, iks *node)
{
  int features, method;
  iks *x;
  ikspak *pak;

  if (!strcmp("stream:features", iks_name(node))) {
    features = iks_stream_features(node);
    if (!use_sasl)
      return IKS_OK;
    if (!use_tls || iks_is_secure(c->parser)) {
      if (c->is_authorized) {
        if (features & IKS_STREAM_BIND) {
          x = iks_make_resource_bind(c->account);
          iks_send(c->parser, x);
          iks_delete(x);
        }
        if (features & IKS_STREAM_SESSION) {
          x = iks_make_session();
          iks_insert_attrib(x, "id", "auth");
          iks_send(c->parser, x);
          iks_delete(x);
        }
      } else {
        method = (features & IKS_STREAM_SASL_MD5)
            ? IKS_SASL_DIGEST_MD5
            : ((features & IKS_STREAM_SASL_MD5) ? IKS_SASL_PLAIN : -1);
        if (method >= 0)
          iks_start_sasl(c->parser, method, c->account->user, c->password);
      }
    }
  } else if (!strcmp("failure", iks_name(node))) {
    return IKS_HOOK;
  } else if (!strcmp("success", iks_name(node))) {
    c->is_authorized = 1;
    iks_send_header(c->parser, c->account->server);
  } else {
    pak = iks_packet(node);
    iks_filter_packet(c->filter, pak);
  }
  return IKS_OK;
}

static int
stream_error_hook(struct context *c, int type, iks *node)
{
  log_printf(0, "Error: Stream error\n");
  return IKS_HOOK;
}

static int
stream_stop_hook(struct context *c, int type, iks *node)
{
  log_printf(3, "Server disconnected\n");
  return IKS_HOOK;
}

static int
jabber_stream_hook(struct context *c, int type, iks *node)
{
  int ret = IKS_OK;

  switch (type) {
    case IKS_NODE_START: ret = stream_start_hook(c, type, node); break;
    case IKS_NODE_NORMAL: ret = stream_normal_hook(c, type, node); break;
    case IKS_NODE_STOP: ret = stream_stop_hook(c, type, node); break;
    case IKS_NODE_ERROR: ret = stream_error_hook(c, type, node); break;
  }
  if (node)
    iks_delete(node);
  return ret;
}

static iksid *
create_account(iksparser *parser, const char *address, const char *pass)
{
  iksid *jid;
  char s[JID_BUF];

  jid = iks_id_new(iks_parser_stack(parser), address);
  strlcpy(me, jid->user, sizeof(me));
  if (jid && !jid->resource) {
    if (sizeof(s) > (strlen(jid->user) + 1 + strlen(jid->server) + 1
                     + strlen(DEFAULT_RESOURCE) + 1)) {
      sprintf(s, "%s@%s/%s", jid->user, jid->server, DEFAULT_RESOURCE);
      jid = iks_id_new(iks_parser_stack(parser), s);
    } else {
      jid = 0;
    }
  }
  return jid;
}

static int
generic_hook(struct context *c, ikspak *pak)
{
  log_printf(1, "Unknown message.\n");
  log_xml(2, "Stanza", pak->x);
  log_printf(2, "\n");
  return IKS_FILTER_EAT;
}

static int
auth_hook(struct context *c, ikspak *pak)
{
  send_status(c, statuses[me_status].show, statuses[me_status].msg);
  return IKS_FILTER_EAT;
}

static int
msg_hook(struct context *c, ikspak *pak)
{
  char *s;
  struct contact *u;

  s = iks_find_cdata(pak->x, "body");
  if (s) {
    u = add_contact(pak->from->partial);
    if (pak->subtype == IKS_TYPE_GROUPCHAT) {
      u->type = pak->subtype;
      print_msg(pak->from->partial, "<%s> %s\n", pak->from->resource, s);
    } else {
      print_msg(pak->from->partial, "<%s> %s\n", pak->from->user, s);
    }
  }
  return IKS_FILTER_EAT;
}

static int
presence_hook(struct context *c, ikspak *pak)
{
  char *show, *status;
  struct contact *u;

  if (pak->subtype == IKS_TYPE_UNAVAILABLE || pak->subtype == IKS_TYPE_ERROR)
    show = STR_OFFLINE;
  else {
    show = iks_find_cdata(pak->x, "show");
    status = iks_find_cdata(pak->x, "status");
  }
  if (!show)
    show = STR_ONLINE;
  if (!status)
    status = "";

  for (u = contacts; u && strcmp(u->jid, pak->from->partial); u = u->next);
  if (u && u->fd > -1) {
    if (u->type == IKS_TYPE_GROUPCHAT) {
      if (!strcasecmp(show, STR_ONLINE) || !strcasecmp(show, STR_OFFLINE))
        print_msg(pak->from->partial, "-!- %s(%s) is %s (%s)\n",
                  pak->from->resource, pak->from->full, show, status);
    } else {
      if ((u->show && strcmp(u->show, show))
          || (u->status && strcmp(u->status, status))) {
        print_msg(pak->from->partial, "-!- %s(%s) is %s (%s)\n",
                  pak->from->user, pak->from->full, show, status);
      }
      strlcpy(u->show, show, sizeof(u->show));
      strlcpy(u->status, status, sizeof(u->status));
    }
  } else {
    print_msg("", "-!- %s(%s) is %s (%s)\n", pak->from->user, pak->from->full,
              show, status);
  }
  return IKS_FILTER_EAT;
}

static int
roster_hook(struct context *c, ikspak *pak)
{
  iks *x;
  char *name, *jid, *sub;
  struct contact *u;

  x = iks_find(pak->x, "query");
  for (x = iks_child(x); x; x = iks_next(x)) {
    if (iks_type(x) == IKS_TAG && !strcmp(iks_name(x), "item")) {
      name = iks_find_attrib(x, "name");
      jid = iks_find_attrib(x, "jid");
      sub = iks_find_attrib(x, "subscription");
      if (!name)
        name = jid;
      for (u = contacts; u && strcmp(u->jid, jid); u = u->next);
      if (u)
        print_msg("", "* %s - %s - (%s) - %s [%s]\n", name, jid,
                  u->show, u->status, sub);
      else
        print_msg("", "* %s - %s - (Offline) - [%s]\n", name, jid, sub);
    }
  }
  return IKS_FILTER_EAT;
}

static int
error_hook(struct context *c, ikspak *pak)
{
  log_printf(0, "Error: XMPP\n");
  log_xml(2, "Stanza", pak->x);
  log_printf(2, "\n");
  return IKS_FILTER_EAT;
}

static iksfilter *
create_filter(struct context *c)
{
  iksfilter *flt;

  flt = iks_filter_new();
  if (flt) {
    iks_filter_add_rule(flt, (iksFilterHook *) generic_hook, c,
                        IKS_RULE_DONE);
    iks_filter_add_rule(flt, (iksFilterHook *) error_hook, c,
                        IKS_RULE_SUBTYPE, IKS_TYPE_ERROR, IKS_RULE_DONE);
    iks_filter_add_rule(flt, (iksFilterHook *) msg_hook, c, IKS_RULE_TYPE,
                        IKS_PAK_MESSAGE, IKS_RULE_DONE);
    iks_filter_add_rule(flt, (iksFilterHook *) presence_hook, c,
                        IKS_RULE_TYPE, IKS_PAK_PRESENCE, IKS_RULE_DONE);
#if 0
    iks_filter_add_rule(flt, (iksFilterHook *) presence_hook, c,
                        IKS_RULE_TYPE, IKS_PAK_S10N, IKS_RULE_SUBTYPE,
                        IKS_TYPE_ERROR, IKS_RULE_DONE);
#endif
    iks_filter_add_rule(flt, (iksFilterHook *) auth_hook, c, IKS_RULE_TYPE,
                        IKS_PAK_IQ, IKS_RULE_SUBTYPE, IKS_TYPE_RESULT,
                        IKS_RULE_ID, "auth", IKS_RULE_DONE);
    iks_filter_add_rule(flt, (iksFilterHook *) roster_hook, c, IKS_RULE_TYPE,
                        IKS_PAK_IQ, IKS_RULE_SUBTYPE, IKS_TYPE_RESULT,
                        IKS_RULE_ID, "roster", IKS_RULE_DONE);
  }
  return flt;
}

static void
cmd_join(struct context *c, struct contact *u, char *s)
{
  char *p;
  iksid *id;

  p = strchr(s + 3, ' ');
  if (p)
    *p = 0;
  id = iks_id_new(iks_parser_stack(c->parser), s + 3);
  add_contact(id->partial);
  if (p) {
    send_message(c, IKS_TYPE_NONE, id->full, p + 1);
    print_msg(id->partial, "<%s> %s\n", me, p + 1);
  }
}

static void
cmd_join_room(struct context *c, struct contact *u, char *s)
{
  char *p;
  iksid *id;

  p = strchr(s + 3, ' ');
  if (p)
    *p = 0;
  id = iks_id_new(iks_parser_stack(c->parser), s + 3);
  u = add_contact(id->partial);
  u->type = IKS_TYPE_GROUPCHAT;
  join_room(c, id->partial, id->resource);
}

static void
cmd_leave(struct context *c, struct contact *u, char *s)
{
  char *p;
  iksid *id;
  struct contact *con;

  p = strchr(s + 3, ' ');
  if (p) {
    *p = 0;
    id = iks_id_new(iks_parser_stack(c->parser), s + 3);
    for (con = contacts; con; con = con->next)
      if (!strcmp(con->jid, id->partial)) {
        rm_contact(con);
        break;
      }
  } else if (u->jid[0]) {
    rm_contact(u);
  }
}

static void
cmd_away(struct context *c, struct contact *u, char *s)
{
  char *p;

  me_status = !me_status;
  p = strchr(s + 3, ' ');
  if (p) {
    *p = 0;
  }
  if (s[2]) {
    strlcpy(statuses[me_status].msg, s + 3, sizeof(statuses[me_status].msg));
  }
  send_status(c, statuses[me_status].show, statuses[me_status].msg);
}

static void
cmd_roster(struct context *c, struct contact *u, char *s)
{
  iks *x;

  x = iks_make_iq(IKS_TYPE_GET, IKS_NS_ROSTER);
  iks_insert_attrib(x, "id", "roster");
  iks_send(c->parser, x);
  iks_delete(x);
}

static void
cmd_who(struct context *c, struct contact *u, char *s)
{
  if (s[2] && s[3])
    request_presence(c, s + 3);
  else if (u->jid[0])
    request_presence(c, u->jid);
}

static void
do_contact_input_string(struct context *c, struct contact *u, char *s)
{
  struct command *cmd;

  if (s[0] == 0)
    return;

  if (s[0] != '/') {
    if (u->jid[0])
      send_message(c, u->type, u->jid, s);
    if (u->type != IKS_TYPE_GROUPCHAT)
      print_msg(u->jid, "<%s> %s\n", me, s);
    return;
  }
  for (cmd = commands; cmd->c; ++cmd)
    if (cmd->c == s[1] && cmd->fn != 0) {
      cmd->fn(c, u, s);
      break;
    }
  if (!cmd->c) {
    send_message(c, u->type, u->jid, s);
    if (u->type != IKS_TYPE_GROUPCHAT)
      print_msg(u->jid, "<%s> %s\n", me, s);
  }
}

static void
handle_contact_input(struct context *c, struct contact *u)
{
  static char buf[PIPE_BUF];

  if (read_line(u->fd, sizeof(buf), buf) == -1) {
    close(u->fd);
    u->fd = open_pipe(u->jid);
    if (u->fd < 0)
      rm_contact(u);
  } else {
    do_contact_input_string(c, u, buf);
  }
}

static int
jabber_do_connection(struct context *c)
{
  int is_running = 1, res, fd, max_fd;
  struct contact *u;
  fd_set fds;
  time_t last_response;
  struct timeval tv;

  add_contact("");
  fd = iks_fd(c->parser);
  last_response = time(0);
  while (is_running) {
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    FD_SET(server_fd, &fds);
    max_fd = fd;
    for (u = contacts; u; u = u->next) {
      if (u->fd >= 0) {
        FD_SET(u->fd, &fds);
        if (u->fd > max_fd)
          max_fd = u->fd;
      }
    }
    tv.tv_sec = keep_alive_ms;
    tv.tv_usec = 0;
    res = select(max_fd + 1, &fds, 0, 0, (keep_alive_ms > 0) ? &tv : 0);
    if (res > 0) {
      if (FD_ISSET(fd, &fds)) {
        switch (iks_recv(c->parser, 1)) {
          case IKS_OK:
            last_response = time(0);
            break;
          default:
            is_running = 0;
        }
      }
      for (u = contacts; u; u = u->next)
        if (FD_ISSET(u->fd, &fds))
          handle_contact_input(c, u);
    } else if (res == 0) {
      if (keep_alive_ms > 0)
        iks_send_raw(c->parser, " ");
    } else
      is_running = 0;
  }
  return 0;
}

static void
log_hook(struct context *c, const char *data, size_t size, int is_incoming)
{
  if (iks_is_secure(c->parser))
    fprintf(stderr, "[&] ");
  fprintf(stderr, (is_incoming) ? "<-\n" : "->\n");
  fwrite(data, size, 1, stderr);
  fputs("\n\n", stderr);
}

static int
jabber_connect(iksparser *p, iksid *jid, const char *server)
{
  int e;

  e = iks_connect_tcp(p, (server) ? server : jid->server, IKS_JABBER_PORT);
  switch (e) {
  case IKS_OK:
    break;
  case IKS_NET_NODNS:
    log_printf(0, "Error: Hostname lookup failed\n");
    break;
  case IKS_NET_NOCONN:
    log_printf(0, "Error: Connection failed\n");
    break;
  default:
    log_printf(0, "Error: I/O\n");
  }
  return e != IKS_OK;
}

static int
jabber_process(const char *address, const char *server, const char *pass)
{
  int ret = 1;
  struct context c = { 0 };

  c.parser = iks_stream_new(IKS_NS_CLIENT, &c,
                            (iksStreamHook *) jabber_stream_hook);
  if (c.parser == 0)
    return 1;
  if (is_log_xml)
    iks_set_log_hook(c.parser, (iksLogHook *) log_hook);
  c.account = create_account(c.parser, address, pass);
  if (c.account) {
    c.password = (char *)pass;
    c.filter = create_filter(&c);
    if (c.filter && jabber_connect(c.parser, c.account, server) == 0) {
      ret = jabber_do_connection(&c);
    }
  }
  iks_parser_delete(c.parser);
  return ret;
}

static void
usage(void)
{
  fprintf(stderr, "%s",
    "ji - jabber it - " VERSION "\n"
    "(C)opyright 2010 Ramil Farkhshatov\n"
    "usage: ji [-r <jabber dir>] [-j <jid>] [-s <server>] [-n <nick>]\n"
    "          [-p <file with password>]\n");
}

static int
read_pw(const char *filename, int pw_bytes, char *pw)
{
  FILE *f;
  int len;

  f = fopen(filename, "r");
  if (!f)
    return 1;

  fgets(pw, pw_bytes, f);
  fclose(f);

  len = strlen(pw);
  if (pw[len - 1] == '\n')
    pw[len - 1] = 0;

  return 0;
}

int
main(int argc, char *argv[])
{
  int i;
  char *jid = 0, *pwfile = 0, *server = 0, *s;
  char pw[PW_BUF];

  s = getenv("HOME");
  snprintf(rootdir, sizeof(rootdir), "%s/mnt/jabber", (s) ? s : ".");
  s = getenv("USER");
  strlcpy(me, (s) ? s : "me", sizeof(me));

  for (i = 1; i < argc - 1 && argv[i][0] == '-'; ++i) {
    switch (argv[i][1]) {
      case 'r': strlcpy(rootdir, argv[++i], sizeof(rootdir)); break;
      case 'n': strlcpy(me, argv[++i], sizeof(me)); break;
      case 'j': jid = argv[++i]; break;
      case 's': server = argv[++i]; break;
      case 'p': pwfile = argv[++i]; break;
      default: usage(); return 1;
    }
  }
  if (!(jid && pwfile)) {
    usage();
    return 1;
  }
  if (read_pw(pwfile, sizeof(pw), pw))
    return 1;
  if (jabber_process(jid, server, pw)) {
    log_printf(0, "Connection error\n");
    return 1;
  }
  return 0;
}
