
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <sys/time.h>
#include <stdint.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "sr_protocol.h"
#include "sr_router.h"

#define MIN_PORT_NUMBER 1024
#define MAX_PORT_NUMBER 65535

typedef enum {
  nat_mapping_icmp,
  nat_mapping_tcp,
  nat_mapping_udp
} sr_nat_mapping_type;

typedef enum
{
  nat_internal,
  nat_external
} sr_nat_incoming;

typedef enum
{
  state_closed_1,
  state_listen,
  state_syn_sent,
  state_syn_rcvd,
  state_estab,
  state_fin_wait_1,
  state_fin_wait_2,
  state_closing,
  state_close_wait,
  state_last_ack,
  state_time_wait,
  state_closed_2
} sr_tcp_conn_state;

struct sr_nat_connection
{
  /* add TCP connection state data members here */
  sr_tcp_conn_state state;
  time_t last_updated;
  uint32_t dst_ip;
  uint16_t dst_port;

  struct sr_nat_connection *next;
};

struct sr_nat_unsol_syn
{
  #define UNSOL_TIMEOUT 6
  time_t time_received;
  uint16_t aux_ext;
  uint8_t *packet;
  struct sr_nat_unsol_syn *next;
};

struct sr_nat_mapping {
  sr_nat_mapping_type type;
  uint32_t ip_int; /* internal ip addr */
  uint32_t ip_ext; /* external ip addr */
  uint16_t aux_int; /* internal port or icmp id */
  uint16_t aux_ext; /* external port or icmp id */
  time_t last_updated; /* use to timeout mappings */
  struct sr_nat_connection *conns; /* list of connections. null for ICMP */
  struct sr_nat_mapping *next;
};

struct sr_nat {
  /* add any fields here */
  struct sr_nat_mapping *mappings;
  struct sr_nat_unsol_syn *unsol;
  unsigned int icmp_timeout;
  unsigned int tcp_tran_timeout;
  unsigned int tcp_est_timeout;

  /* threading */
  pthread_mutex_t lock;
  pthread_mutexattr_t attr;
  pthread_attr_t thread_attr;
  pthread_t thread;
};


int sr_nat_init(struct sr_instance *sr, unsigned int icmp_timeout,
                unsigned int tcp_tran_timeout, unsigned int tcp_est_timeout);     /* Initializes the nat */
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *sr_ptr);  /* Periodic Timout */

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type );

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );

/* Insert a new mapping into the nat's mapping table.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint32_t ip_ext, uint16_t aux_int, sr_nat_mapping_type type );

void sr_nat_insert_unsol(struct sr_nat *nat, uint8_t *packet, uint16_t aux_ext,
                         unsigned int len);

void insert_mapping(struct sr_nat *nat, struct sr_nat_mapping *mapping);
uint16_t get_available_port(struct sr_nat *nat);

void nat_handlepacket(struct sr_instance *sr, uint8_t *packet,
                      unsigned int len, char *interface);

void nat_handle_internal(struct sr_instance *sr, uint8_t *packet,
                         unsigned int len, char *interface);

void nat_handle_external(struct sr_instance *sr, uint8_t *packet,
                         unsigned int len, char *interface);

struct sr_nat_connection *nat_connection_lookup(struct sr_nat *nat, struct sr_nat_mapping *mapping,
                                               uint32_t dst_ip, uint16_t dst_port);

struct sr_nat_connection *sr_nat_insert_connection(struct sr_nat *nat, struct sr_nat_mapping *mapping,
                                                   uint32_t dst_ip, uint16_t dst_port);

void sr_nat_apply_mapping_internal(struct sr_nat_mapping *, uint8_t *, unsigned int);
void sr_nat_apply_mapping_external(struct sr_nat_mapping *, uint8_t *, unsigned int);

update_icmp_mapping(struct sr_nat *nat, struct sr_nat_mapping *mapping);

int is_flag(sr_tcp_hdr_t *tcp_hdr);
int is_flag_type(sr_tcp_hdr_t *tcp_hdr, uint8_t flag);

int update_conn(struct sr_nat_connection *conn, sr_tcp_hdr_t *tcp_hdr);

#endif
