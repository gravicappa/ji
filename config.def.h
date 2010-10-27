int keep_alive_ms = 12000;
int log_level = 10;
int me_status = 0;
int use_tls = 1;
int use_sasl = 1;
int use_plain = 0;
int is_log_xml = 0;
char *root = "talk";

#define DEFAULT_RESOURCE "ji"
#define STR_ONLINE "online"
#define STR_OFFLINE "offline"
#define PING_TIMEOUT 300
#define JID_BUF 256
#define PW_BUF 256
#define PIPE_BUF 4096
#define PATH_BUF 512
#define STATUS_BUF 256

struct status {
  enum ikshowtype show;
  char msg[STATUS_BUF];
} stats[] = {
  {IKS_SHOW_AVAILABLE, ""},
  {IKS_SHOW_AWAY, "Away."},
};
