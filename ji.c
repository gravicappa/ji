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
#include <time.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <iksemel.h>
#include "config.h"

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
  {0, 0}
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
  iksparser *parser;
  iksid *jid;
  iksfilter *filter;

  char pw[PW_BUF];
  int is_authorized;
};

int is_negotiated = 0;
struct contact *contacts = 0;
char rootdir[PATH_BUF] = "";
char me[JID_BUF] = "";

static void make_path(size_t dst_bytes, char *dst, const char *dir,
                      const char *file);
static int open_pipe(const char *name);
static void send_status(struct context *c, enum ikshowtype status,
                        const char *msg);
static void send_message(struct context *c, enum iksubtype type,
                  const char *to, const char *msg);

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
  log_printf(level, "\n%s:\n%s\n\n", prefix, s);
  iks_free(s);
}

static struct contact *
add_contact(const char *jid)
{
  char infile[PATH_BUF];
  struct contact *u;

  for (u = contacts; u && strcmp(jid, u->jid); u = u->next);
  if (u)
    return u;

  make_path(sizeof(infile), infile, jid, "in");
  if (!infile[0])
    return 0;

  u = calloc(1, sizeof(struct contact));
  if (!u)
    return 0;

  snprintf(u->jid, sizeof(u->jid), "%s", jid);
  u->fd = open_pipe(u->jid);
  u->next = contacts;
  u->type = IKS_TYPE_CHAT;
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
    if (p && p->next == c)
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
make_path(size_t dst_bytes, char *dst, const char *dir, const char *file)
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
  } else if (!use_sasl) {
    iks *x;
    char *sid = 0;

    if (!use_plain)
      sid = iks_find_attrib(node, "id");
    x = iks_make_auth(c->jid, c->pw, sid);
    iks_insert_attrib(x, "id", "auth");
    iks_send(c->parser, x);
    iks_delete(x);
  }
  return IKS_OK;
}

static int
stream_normal_hook(struct context *c, int type, iks *node)
{
  int features;
  iks *x;
  ikspak *pak;

  if (!strcmp("stream:features", iks_name(node))) {
    features = iks_stream_features(node);
    if (!use_sasl)
      return IKS_OK;
    if (use_tls && !iks_is_secure(c->parser))
      return IKS_OK;
    if (c->is_authorized) {
      if (features & IKS_STREAM_BIND) {
        x = iks_make_resource_bind(c->jid);
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
      if (features & IKS_STREAM_SASL_MD5)
        iks_start_sasl(c->parser, IKS_SASL_DIGEST_MD5, c->jid->user, c->pw);
      else if (features & IKS_STREAM_SASL_PLAIN)
        iks_start_sasl(c->parser, IKS_SASL_PLAIN, c->jid->user, c->pw);
    }
  } else if (!strcmp("failure", iks_name(node))) {
    return IKS_HOOK;
  } else if (!strcmp("success", iks_name(node))) {
    c->is_authorized = 1;
    iks_send_header(c->parser, c->jid->server);
  } else {
    is_negotiated = 1;
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
init_account(iksparser *parser, const char *address)
{
  iksid *jid;
  char s[JID_BUF];

  jid = iks_id_new(iks_parser_stack(parser), address);
  snprintf(me, sizeof(me), "%s", jid->user);
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
  print_msg("", "-!- %s\n", iks_string(iks_stack(pak->x), pak->x));
  return IKS_FILTER_EAT;
}

static int
auth_hook(struct context *c, ikspak *pak)
{
  send_status(c, stats[me_status].show, stats[me_status].msg);
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
  char *show, *s, *status;
  struct contact *u;

  show = iks_find_cdata(pak->x, "show");
  status = iks_find_cdata(pak->x, "status");
  if (pak->subtype == IKS_TYPE_UNAVAILABLE || pak->subtype == IKS_TYPE_ERROR)
    show = STR_OFFLINE;
  else if (pak->type == IKS_PAK_S10N)
    show = iks_find_attrib(pak->x, "type");

  if (!show)
    show = STR_ONLINE;
  if (!status)
    status = "";
  
  for (s = status; *s; ++s)
    if (*s == '\n')
      *s = '\\';

  for (u = contacts; u && strcmp(u->jid, pak->from->partial); u = u->next);
  if (!u || u->type != IKS_TYPE_GROUPCHAT)
    print_msg("", "-!- %s(%s) is %s (%s)\n", pak->from->user, pak->from->full,
              show, status);
  if (u) {
    if (u->type == IKS_TYPE_GROUPCHAT) {
      if (!strcasecmp(show, STR_ONLINE) || !strcasecmp(show, STR_OFFLINE))
        print_msg(pak->from->partial, "-!- %s(%s) is %s (%s)\n",
                  pak->from->resource, pak->from->full, show, status);
    } else {
      print_msg(pak->from->partial, "-!- %s(%s) is %s (%s)\n",
                pak->from->user, pak->from->full, show, status);
      snprintf(u->show, sizeof(u->show), "%s", show);
      snprintf(u->status, sizeof(u->status), "%s", status);
    }
  }
  return IKS_FILTER_EAT;
}

static int
roster_hook(struct context *c, ikspak *pak)
{
  iks *x;
  char *name, *jid, *sub;
  struct contact *u;

  for (x = iks_child(iks_find(pak->x, "query")); x; x = iks_next(x)) {
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
        print_msg("", "* %s - %s - (%s) - [%s]\n", name, jid, STR_OFFLINE,
                  sub);
    }
  }
  print_msg("", "End of /R list.\n");
  for (x = iks_child(iks_find(pak->x, "query")); x; x = iks_next(x))
    if (iks_type(x) == IKS_TAG && !strcmp(iks_name(x), "item"))
      request_presence(c, iks_find_attrib(x, "jid"));
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
    iks_filter_add_rule(flt, (iksFilterHook *) presence_hook, c,
                        IKS_RULE_TYPE, IKS_PAK_PRESENCE, IKS_RULE_SUBTYPE,
                        IKS_TYPE_ERROR, IKS_RULE_DONE);
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
  if ((id = iks_id_new(iks_parser_stack(c->parser), s + 3))) {
    add_contact(id->partial);
    if (p) {
      send_message(c, IKS_TYPE_NONE, id->full, p + 1);
      print_msg(id->partial, "<%s> %s\n", me, p + 1);
    }
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
  if ((id = iks_id_new(iks_parser_stack(c->parser), s + 3))) {
    u = add_contact(id->partial);
    u->type = IKS_TYPE_GROUPCHAT;
    join_room(c, id->partial, id->resource);
  }
}

static void
cmd_leave(struct context *c, struct contact *u, char *s)
{
  iksid *id;

  if (s[2] && s[3]) {
    id = iks_id_new(iks_parser_stack(c->parser), s + 3);
    if (!id)
      return;
    for (u = contacts; u && strcmp(u->jid, id->partial); u = u->next);
    if (u)
      rm_contact(u);
  } else if (u->jid[0])
    rm_contact(u);
}

static void
cmd_away(struct context *c, struct contact *u, char *s)
{
  me_status = !me_status;
  if (s[2])
    snprintf(stats[me_status].msg, sizeof(stats[me_status].msg), "%s", s + 3);
  send_status(c, stats[me_status].show, stats[me_status].msg);
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
    else
      iks_send_raw(c->parser, s);
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
  struct contact *u, *next;
  fd_set fds;
  time_t last_response;
  struct timeval tv;

  fd = iks_fd(c->parser);
  add_contact("");
  last_response = time(0);
  while (is_running) {
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    max_fd = fd;
    for (u = contacts; u; u = u->next) {
      if (u->fd >= 0) {
        FD_SET(u->fd, &fds);
        if (u->fd > max_fd)
          max_fd = u->fd;
      }
    }
    tv.tv_sec = 0;
    tv.tv_usec = keep_alive_ms * 1000;
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
      for (u = contacts; u; u = next) {
        next = u->next;
        if (FD_ISSET(u->fd, &fds))
          handle_contact_input(c, u);
      }
    } else if (res == 0) {
      if (keep_alive_ms > 0 && is_negotiated)
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

  e = iks_connect_via(p, (server) ? server : jid->server, IKS_JABBER_PORT,
                      jid->server);
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
jabber_process(struct context *c, const char *server)
{
  if (is_log_xml)
    iks_set_log_hook(c->parser, (iksLogHook *) log_hook);
  c->filter = create_filter(c);
  if (c->filter && jabber_connect(c->parser, c->jid, server) == 0) {
    return jabber_do_connection(c);
  }
  return 1;
}

static void
usage(void)
{
  fprintf(stderr, "%s",
    "ji - jabber it - " VERSION "\n"
    "(C)opyright 2010 Ramil Farkhshatov\n"
    "usage: ji [-r <jabber dir>] [-j <jid>] [-s <server>] [-n <nick>]\n");
}

int
main(int argc, char *argv[])
{
  int i, ret;
  char *jid = 0, *server = 0, *s;
  char path_buf[PATH_BUF];
  struct context c = { 0 };

  s = getenv("HOME");
  snprintf(path_buf, sizeof(path_buf), "%s/%s", (s) ? s : ".", root);
  s = getenv("USER");
  snprintf(me, sizeof(me), "%s", (s) ? s : "me");

  for (i = 1; i < argc - 1 && argv[i][0] == '-'; ++i) {
    switch (argv[i][1]) {
      case 'r': snprintf(path_buf, sizeof(path_buf), "%s", argv[++i]); break;
      case 'n': snprintf(me, sizeof(me), "%s", argv[++i]); break;
      case 'j': jid = argv[++i]; break;
      case 's': server = argv[++i]; break;
      default: usage(); return 1;
    }
  }
  if (!jid) {
    usage();
    return 1;
  }
  if (read_line(0, sizeof(c.pw), c.pw))
    return 1;

  c.parser = iks_stream_new(IKS_NS_CLIENT, &c,
                            (iksStreamHook *) jabber_stream_hook);
  if (!c.parser)
    return 1;

  c.jid = init_account(c.parser, jid);
  if (!c.jid)
    return 1;

  snprintf(rootdir, sizeof(rootdir), "%s/%s", path_buf, c.jid->partial);

  if ((ret = jabber_process(&c, server)))
    log_printf(0, "Connection error\n");
  iks_parser_delete(c.parser);

  return ret;
}
