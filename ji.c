#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <iksemel.h>

#define MAX_ADDRESS 64

struct contact {
  int fd;

  iksid *jid;
  char *show;
  char *status;

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

char *address_from_iksid(iksid *jid, char *resource);

int stream_start_hook(struct context *s, int type, iks *node);
int stream_normal_hook(struct context *s, int type, iks *node);
int stream_stop_hook(struct context *s, int type, iks *node);
int stream_error_hook(struct context *s, int type, iks *node);

void send_status(struct context *c, enum ikshowtype status, const char *msg);
void send_message(struct context *c, enum iksubtype type, 
                  const char *to, const char *msg);
void request_roster(struct context *c);

#define DEFAULT_RESOURCE "CCCP"

int log_level = 10;

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

void
add_contact(iksid *jid)
{
  struct contact *u;

  for (u = contacts; u; u = u->next)
    if (!iks_id_cmp(jid, u->jid, IKS_ID_PARTIAL))
      return;

  u = calloc(1, sizeof(struct contact));
  u->fd = -1;
  u->jid = jid;
  u->next = contacts;
  contacts = u;
}

void
rm_contact(struct contact *c)
{
  struct contact *p;

  if (c == contacts)
    contacts = contacts->next;
  else {
    for (p = contacts; p && p->next != c; p = p->next);
    if (p->next == c)
      p->next = c->next;
  }

  free(c->show);
  free(c->status);

  if (c->fd >= 0) {
    close(c->fd);
    /* remove fifo */
  }
}

void
send_status(struct context *c, enum ikshowtype status, const char *msg)
{
  iks *x;

  x = iks_make_pres(status, msg);
  log_xml(5, "Presence", x);
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
  log_xml(5, "Presence request", x);
  iks_send(c->parser, x);
  iks_delete(x);
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
  log_printf(0, ";; unknown message\n");
  return IKS_FILTER_EAT;
}

int
auth_hook(struct context *c, ikspak *pak)
{
  log_checkpoint;

  send_status(c, IKS_SHOW_AVAILABLE, "Testing");
  send_message(c, IKS_TYPE_NONE, "ramil.fh@jabber.ru", "Test");
  request_roster(c);

  return IKS_FILTER_EAT;
}

int
msg_hook(struct context *c, ikspak *pak)
{
  iks *x = 0;
  char *s;

  s = iks_find_cdata(pak->x, "body");
  printf("\nMessage from %s:\n%s\n\n", pak->from->full, s);
  return IKS_FILTER_EAT;
}

int
presence_hook(struct context *c, ikspak *pak)
{
  iks *x;
  char *show, *status;
  struct contact *u;

  if (pak->subtype == IKS_TYPE_ERROR) {
    show = "offline";
    status = "";
  } else {
    show = iks_find_cdata(pak->x, "show");
    status = iks_find_cdata(pak->x, "status");
    if (!show)
      show = "online";
  }

  for (u = contacts; u; u = u->next) {
    if (!iks_id_cmp(u->jid, pak->from, IKS_ID_PARTIAL)) {
      free(u->show);
      free(u->status);
      u->show = strdup(show);
      u->status = (status) ? strdup(status) : 0;
      break;
    }
  }
  for (u = contacts; u; u = u->next) {
    printf("%s (%s) %s\n", u->jid->full, u->show, u->status);
  }
  return IKS_FILTER_EAT;
}

int
roster_hook(struct context *c, ikspak *pak)
{
  iks *x, *y;
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
        request_presence(c, jid);
        id = iks_id_new(iks_parser_stack(c->parser), jid);
        add_contact(id);
      }
    }
  }
  return IKS_FILTER_EAT;
}

int
error_hook(struct context *c, ikspak *pak)
{
  log_printf(0, ";; Error occured\n");
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

int
jabber_do_connection(iksparser *parser)
{
  int e, is_running = 1, res, fd, max_fd;
  fd_set fds;

  fd = iks_fd(parser);

  max_fd = fd;
  while (is_running) {
    FD_ZERO(&fds);
    FD_SET(fd, &fds);

    res = select(max_fd + 1, &fds, 0, 0, 0);
    if (res > 0) {
      if (FD_ISSET(fd, &fds)) {
        switch (iks_recv(parser, 1)) {
          case IKS_OK:
            break;
          default:
            is_running = 0;
        }
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
        jabber_do_connection(c.parser);
      }
    }
  }
  log_checkpoint;
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
  log_checkpoint;
  if (jabber_process("ramil.fh@jabber.ru", "z1hfvbkm1")) {
    fprintf(stderr, "Connection error\n");
    return -1;
  }
  return 0;
}
