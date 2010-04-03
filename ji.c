#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <iksemel.h>

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

int stream_start_hook(struct context *s, int type, iks *node);
int stream_normal_hook(struct context *s, int type, iks *node);
int stream_stop_hook(struct context *s, int type, iks *node);
int stream_error_hook(struct context *s, int type, iks *node);

struct stream_hook {
  int type;
  int (*fn)(struct context *, int, iks *);
} stream_hooks[] = {
  {IKS_NODE_START, stream_start_hook},
  {IKS_NODE_NORMAL, stream_normal_hook},
  {IKS_NODE_ERROR, stream_error_hook},
  {IKS_NODE_STOP, stream_stop_hook},
  {0, 0}
};

#define DEFAULT_RESOURCE "CCCP"

int log_level = 3;

void
log_printf(int level, const char *fmt, ...)
{
  va_list args;

  if (level >= log_level) {
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
  }
}

int
jabber_stream_hook(struct context *c, int type, iks *node)
{
  int ret = IKS_OK, i;

  for (i = 0; stream_hooks[i].fn; ++i) {
    if (stream_hooks[i].type == type) {
      ret = stream_hooks[i].fn(c, type, node);
      break;
    }
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
  iksid *acc;

  acc = iks_id_new(iks_parser_stack(parser), address);
  if (acc && !acc->resource) {
    char *s;
    int nuser, nserver, nres;

    s = iks_malloc(strlen(acc->user) + 1 + strlen(acc->server) + 1 
                   + strlen(DEFAULT_RESOURCE) + 1);
    if (s) {
      sprintf(s, "%s@%s/%s", acc->user, acc->server, DEFAULT_RESOURCE);
      acc = iks_id_new(iks_parser_stack(parser), s);
      iks_free(s);
    } else {
      acc = 0;
    }
  }
  return acc;
}

int
generic_hook(void *p, ikspak *pak)
{
  log_printf(0, ";; unknown message\n");
  return IKS_FILTER_EAT;
}

int
auth_hook(void *p, ikspak *pak)
{
  return IKS_FILTER_EAT;
}

int
msg_hook(void *p, ikspak *pak)
{
  return IKS_FILTER_EAT;
}

int
error_hook(void *p, ikspak *pak)
{
  log_printf(0, ";; Error\n");
  return IKS_FILTER_EAT;
}

iksfilter *
create_filter()
{
  iksfilter *flt;

  flt = iks_filter_new();
  if (!flt)
    return 0;

  iks_filter_add_rule(flt, generic_hook, 0, IKS_RULE_DONE);
  iks_filter_add_rule(flt, error_hook, 0, IKS_RULE_SUBTYPE, IKS_TYPE_ERROR,
                      IKS_RULE_DONE);
  iks_filter_add_rule(flt, msg_hook, 0, IKS_RULE_TYPE, IKS_PAK_MESSAGE, 
                      IKS_RULE_DONE);
  iks_filter_add_rule(flt, auth_hook, 0, IKS_RULE_TYPE, IKS_PAK_IQ,
                      IKS_RULE_SUBTYPE, IKS_TYPE_RESULT, IKS_RULE_ID, "auth",
                      IKS_RULE_DONE);
  return flt;
}

int
jabber_connect(iksparser *parser, iksid *jid) {
  int e;

  e = iks_connect_tcp(parser, jid->server, IKS_JABBER_PORT);
  switch(e) {
    case IKS_OK:
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

int
jabber_process(const char *address, const char *pass)
{
  int e;
  struct context c = {0};

  c.parser = iks_stream_new(IKS_NS_CLIENT, 0, jabber_stream_hook);
  if (c.parser == 0)
    return 1;

  c.account = create_account(c.parser, address, pass);
  if (c.account) {
    c.password = pass;
    c.filter = create_filter();
    if (c.filter) {
      if (jabber_connect(c.parser, c.account) == 0) {
        jabber_do_connection(c.parser);
      }
    }
  }
  iks_parser_delete(c.parser);
}

int
main(int argc, char *argv[])
{
  if (jabber_process("ramil.fh@jabber.ru", "z1hfvbkm1")) {
    fprintf(stderr, "Connection error\n");
    return -1;
  }
  return 0;
}
