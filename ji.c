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

#define DEFAULT_RESOURCE "CCCP"
#define STR_ONLINE "Online"
#define STR_OFFLINE "Offline"
#define JID_BUF 256
#define PIPE_BUF 4096
#define PATH_BUF 512
#define STATUS_BUF 256
#define PING_TIMEOUT 300

int log_level = 10;
char me[256] = "yoda";

struct contact {
  int fd;

  char jid[JID_BUF];
  char show[STATUS_BUF];
  char status[STATUS_BUF];

  struct contact *next;
};

struct context {
  char *password;
  iksparser *parser;
  iksid *account;
  iksfilter *filter;

  int is_authorized;
  int opt_use_tls;
  int opt_use_sasl;
  int opt_use_plain;
};

struct contact *contacts = 0;
char rootdir[PATH_BUF] = "";
int server_fd = -1;

char *address_from_iksid(iksid *jid, char *resource);

int stream_start_hook(struct context *s, int type, iks *node);
int stream_normal_hook(struct context *s, int type, iks *node);
int stream_stop_hook(struct context *s, int type, iks *node);

static void make_path(int dst_bytes, char *dst, const char *dir,
                      const char *file);
static int open_channel(const char *name);

void send_status(struct context *c, enum ikshowtype status, const char *msg);
void send_message(struct context *c, enum iksubtype type,
                  const char *to, const char *msg);
void request_roster(struct context *c);

void
log_printf(int level, const char *fmt, ...)
{
  va_list args;

  if (level <= log_level) {
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
  }
}

#define log_checkpoint \
  log_printf(5, ";; %s:%d %s\n", __FILE__, __LINE__, __func__)

void
log_xml(int level, const char *prefix, iks *x)
{
  char *s;

  s = iks_string(0, x);
  log_printf(level, ";; %s: %s\n", prefix, s);
  iks_free(s);
}

struct contact *
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

  u->fd = open_channel(infile);
  strncpy(u->jid, jid, sizeof(u->jid) - 1);
  u->jid[sizeof(u->jid) - 1] = 0;
  u->next = contacts;
  strcpy(u->show, STR_OFFLINE);
  strcpy(u->status, "");
  contacts = u;

  return u;
}

void
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
  char tmp[256];
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

static void
make_path(int dst_bytes, char *dst, const char *dir, const char *file)
{
  dst[0] = 0;
  if (dst_bytes > strlen(rootdir) + 1 + strlen(dir) + 1 + strlen(file) + 1) {
    sprintf(dst, "%s/%s/%s", rootdir, dir, file);
  }
}

static int
open_channel(const char *name)
{
  char path[PATH_BUF];

  make_path(sizeof(path), path, name, "in");
  if (!path[0])
    return -1;
  if (access(path, F_OK) == -1)
    mkfifo(path, S_IRWXU);
  return open(path, O_RDONLY | O_NONBLOCK, 0);
}

void
print_msg(const char *from, const char *fmt, ...)
{
  va_list args;
  char path[PATH_BUF], date[128];
  struct tm *tm;
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
    strftime(date, sizeof(date), "%F %R", localtime(&t));
    fprintf(f, "%s ", date);
    va_start(args, fmt);
    vfprintf(f, fmt, args);
    va_end(args);
    fclose(f);
  }
}

void
send_status(struct context *c, enum ikshowtype status, const char *msg)
{
  iks *x;

  x = iks_make_pres(status, msg);
  //log_xml(5, "Presence", x);
  iks_send(c->parser, x);
  iks_delete(x);
}

void
send_message(struct context *c, enum iksubtype type, const char *to,
             const char *msg)
{
  iks *x;

  x = iks_make_msg(type, to, msg);
  iks_send(c->parser, x);
  iks_delete(x);
}

void
request_roster(struct context *c)
{
  iks *x;

  x = iks_make_iq(IKS_TYPE_GET, IKS_NS_ROSTER);
  iks_insert_attrib(x, "id", "roster");
  iks_send(c->parser, x);
  iks_delete(x);
}

void
request_presence(struct context *c, const char *to)
{
  iks *x;

  x = iks_new("presence");

  iks_insert_attrib(x, "type", "probe");
  iks_insert_attrib(x, "to", to);
  //log_xml(5, "Presence request", x);
  iks_send(c->parser, x);
  iks_delete(x);
}

int
stream_start_hook(struct context *c, int type, iks *node)
{
  if (c->opt_use_tls && !iks_is_secure(c->parser)) {
    iks_start_tls(c->parser);
  }
  if (!c->opt_use_sasl) {
    iks *x;
    char *sid = 0;

    if (!c->opt_use_plain)
      sid = iks_find_attrib(node, "id");
    x = iks_make_auth(c->account, c->password, sid);
    iks_insert_attrib(x, "id", "auth");
    iks_send(c->parser, x);
    iks_delete(x);
  }
  return IKS_OK;
}

int
stream_normal_hook(struct context *c, int type, iks *node)
{
  int features, method;
  iks *x;
  ikspak *pak;

  if (!strcmp("stream:features", iks_name(node))) {
    features = iks_stream_features(node);
    if (!c->opt_use_sasl)
      return IKS_OK;
    if (!c->opt_use_tls || iks_is_secure(c->parser)) {
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

int
stream_error_hook(struct context *c, int type, iks *node)
{
  log_printf(0, ";; Error: Stream error\n");
  return IKS_HOOK;
}

int
stream_stop_hook(struct context *c, int type, iks *node)
{
  log_printf(3, ";; Server disconnected\n");
  return IKS_HOOK;
}

int
jabber_stream_hook(struct context *c, int type, iks *node)
{
  int ret = IKS_OK;

  switch (type) {
    case IKS_NODE_START:
      ret = stream_start_hook(c, type, node);
      break;
    case IKS_NODE_NORMAL:
      ret = stream_normal_hook(c, type, node);
      break;
    case IKS_NODE_STOP:
      ret = stream_stop_hook(c, type, node);
      break;
    case IKS_NODE_ERROR:
      ret = stream_error_hook(c, type, node);
      break;
  }
  if (node)
    iks_delete(node);
  return ret;
}

iksid *
create_account(iksparser *parser, const char *address, const char *pass)
{
  iksid *jid;

  jid = iks_id_new(iks_parser_stack(parser), address);
  if (jid && !jid->resource) {
    char *s;

    s = iks_malloc(strlen(jid->user) + 1 + strlen(jid->server) + 1
                         + strlen(DEFAULT_RESOURCE) + 1);
    if (s) {
      sprintf(s, "%s@%s/%s", jid->user, jid->server, DEFAULT_RESOURCE);
      jid = iks_id_new(iks_parser_stack(parser), s);
      iks_free(s);
    } else {
      jid = 0;
    }
  }
  return jid;
}

int
generic_hook(struct context *c, ikspak *pak)
{
  log_printf(1, ";; Unknown message.\n");
  log_xml(2, "Stanza", pak->x);
  log_printf(2, ";; \n");
  return IKS_FILTER_EAT;
}

int
auth_hook(struct context *c, ikspak *pak)
{
  send_status(c, IKS_SHOW_AVAILABLE, "Testing");
  send_message(c, IKS_TYPE_NONE, "ramil.fh@jabber.ru", "Test");
  request_roster(c);

  return IKS_FILTER_EAT;
}

int
msg_hook(struct context *c, ikspak *pak)
{
  iks *x = 0;
  char *s, *path;
  struct contact *u;

  s = iks_find_cdata(pak->x, "body");
  print_msg(pak->from->partial, "<%s> %s\n", pak->from->user, s);
  return IKS_FILTER_EAT;
}

int
presence_hook(struct context *c, ikspak *pak)
{
  iks *x;
  char *show, *status;
  struct contact *u;
  int printed = 0;

  if (pak->subtype == IKS_TYPE_ERROR) {
    show = STR_OFFLINE;
  } else {
    show = iks_find_cdata(pak->x, "show");
    status = iks_find_cdata(pak->x, "status");
  }
  if (!show)
    show = STR_ONLINE;
  if (!status)
    status = "";

  for (u = contacts; u; u = u->next) {
    if (!strcmp(u->jid, pak->from->partial)) {
      if (u->fd > -1 && ((u->show && strcmp(u->show, show))
                         || (u->status && strcmp(u->status, status)))) {
        print_msg(pak->from->partial, "-!- %s(%s) is %s (%s)\n",
                  pak->from->user, pak->from->full, show, status);
      }
      strncpy(u->show, show, sizeof(u->show) - 1);
      u->show[sizeof(u->show) - 1] = 0;
      strncpy(u->status, status, sizeof(u->status) - 1);
      u->status[sizeof(u->status) - 1] = 0;
      break;
    }
  }
  if (!u || u->fd < 0) {
    print_msg("", "-!- %s(%s) is %s (%s)\n", pak->from->user, pak->from->full,
              show, status);
  }
  return IKS_FILTER_EAT;
}

int
roster_hook(struct context *c, ikspak *pak)
{
  iks *x;
  iksid *id;
  char *name, *jid, *sub;

  x = iks_find(pak->x, "query");
  if (x) {
    for (x = iks_child(x); x; x = iks_next(x)) {
      if (iks_type(x) == IKS_TAG && !strcmp(iks_name(x), "item")) {
        name = iks_find_attrib(x, "name");
        jid = iks_find_attrib(x, "jid");
        sub = iks_find_attrib(x, "subscription");
        if (!name)
          name = jid;
        //add_contact(iks_id_new(iks_parser_stack(c->parser), jid));
      }
    }
  }
  return IKS_FILTER_EAT;
}

int
error_hook(struct context *c, ikspak *pak)
{
  log_printf(0, ";; Error occured\n");
  log_xml(2, "Stanza", pak->x);
  log_printf(2, ";; \n");
  return IKS_FILTER_EAT;
}

iksfilter *
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

int
jabber_connect(iksparser *parser, iksid *jid) {
  int e;

  e = iks_connect_tcp(parser, jid->server, IKS_JABBER_PORT);
  switch(e) {
    case IKS_OK:
      log_printf(3, ";; Connected to server\n");
      break;
    case IKS_NET_NODNS:
      log_printf(0, ";; Error: hostname lookup failed\n");
      break;
    case IKS_NET_NOCONN:
      log_printf(0, ";; Error: connection failed\n");
      break;
    default:
      log_printf(0, ";; Error: IO\n");
  }
  return e != IKS_OK;
}

void
do_contact_input_string(struct context *c, struct contact *u, char *s)
{
  char *p;
  iksid *id;
  struct contact *con;

  if (s[0] == 0)
    return;

  if (s[0] != '/') {
    send_message(c, IKS_TYPE_NONE, u->jid, s);
    print_msg(u->jid, "<%s> %s\n", me, s);
    return;
  }
  switch (s[1]) {
    case 'j':
      p = strchr(s + 3, ' ');
      if (p)
        *p = 0;
      id = iks_id_new(iks_parser_stack(c->parser), s + 3);
      add_contact(id->partial);
      if (p) {
        send_message(c, IKS_TYPE_NONE, id->full, p + 1);
        print_msg(id->partial, "<%s> %s\n", me, p + 1);
      }
      break;
    case 'l':
      p = strchr(s + 3, ' ');
      if (p) {
        *p = 0;
        id = iks_id_new(iks_parser_stack(c->parser), s + 3);
        for(con = contacts; con; con = con->next)
          if (!strcmp(con->jid, id->partial)) {
            rm_contact(con);
            break;
          }
      } else if (u->jid[0]) {
        rm_contact(u);
      }
      break;
    default:
      send_message(c, IKS_TYPE_NONE, u->jid, s);
      print_msg(u->jid, "<%s> %s\n", me, s);
  }
}

int
handle_contact_input(struct context *c, struct contact *u)
{
  static char buf[PIPE_BUF];

  if (read_line(u->fd, sizeof(buf), buf) == -1) {
    close(u->fd);
    u->fd = open_channel(u->jid);
    if (u->fd < 0)
      rm_contact(u);
  } else {
    do_contact_input_string(c, u, buf);
  }
}

int
jabber_do_connection(struct context *c)
{
  int e, is_running = 1, res, fd, max_fd;
  struct contact *u;
  fd_set fds;
  time_t last_response;

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
    res = select(max_fd + 1, &fds, 0, 0, 0);
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
      if (time(0) - last_response >= PING_TIMEOUT) {
        log_printf(0, ";; Ping timeout\n");
        is_running = 0;
      }
      for (u = contacts; u; u = u->next)
        if (FD_ISSET(u->fd, &fds)) {
          handle_contact_input(c, u);
        }
    } else {
      break;
    }
  }
  return 0;
}

void
log_hook(struct context *c, const char *data, size_t size, int is_incoming)
{
  if (iks_is_secure(c->parser))
    fprintf(stderr, "[&] ");
  fprintf(stderr, (is_incoming) ? "<-\n" : "->\n");
  fwrite(data, size, 1, stderr);
  fputs("\n\n", stderr);
}

int
jabber_process(const char *address, const char *pass)
{
  int e;
  struct context c = {0};

  c.opt_use_sasl = 1;
  c.parser = iks_stream_new(IKS_NS_CLIENT, &c,
                            (iksStreamHook *)jabber_stream_hook);
  if (c.parser == 0)
    return 1;

  //iks_set_log_hook(c.parser, (iksLogHook *) log_hook);
  c.account = create_account(c.parser, address, pass);
  if (c.account) {
    c.password = (char *)pass;
    c.filter = create_filter(&c);
    if (c.filter) {
      if (jabber_connect(c.parser, c.account) == 0) {
        jabber_do_connection(&c);
      }
    }
  }
  iks_parser_delete(c.parser);
  c.account = 0;
  c.filter = 0;
  c.parser = 0;
}

#if 0
void
cleanup()
{
  struct contact *c, *p;
  c = contacts;
  while ((p = c)) {
    c = c->next;
    rm_contact(c);
  }
}
#endif

int
main(int argc, char *argv[])
{
  snprintf(rootdir, sizeof(rootdir), "%s/mnt/jabber", getenv("HOME"));
  log_printf(5, "rootdir: '%s'\n", rootdir);
  if (jabber_process("ramil.fh@jabber.ru", "z1hfvbkm1")) {
    fprintf(stderr, "Connection error\n");
    return -1;
  }
  return 0;
}
