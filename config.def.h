int keep_alive_ms = 12000;
int log_level = 0;
int me_status = 0;
int use_tls = 1;
int use_sasl = 1;
int use_plain = 0;
int is_log_xml = 0;
int show_log = 0;
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
#define ID_BUF 64
#define DATA_BUF 512

struct status {
  char *show;
  char msg[STATUS_BUF];
} stats[] = {
  {"online", ""},
  {"away", "Away."},
};
