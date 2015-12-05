#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_utils.h"
#include <unistd.h>

/*void mapping_exists(struct sr_nat *nat)
{
  if(nat->mappings)
  {
    printf("MAPPINGS EXISTS SUPER OMG YEAH THEY HERE NOW WE CAN PLAY\n");
    if(nat->mappings->conns == NULL)
    {
      printf("OMG BUT NO CONNECTIONS\n");
    }
  }
  else
  {
    printf("OMG NO MAPPINGS WHAT DO WE DO ALL DAY AND NIGHT, MASTERBATE?\n");
  }
}*/
/* Initializes the nat */
int sr_nat_init(struct sr_instance *sr, unsigned int icmp_timeout,
                unsigned int tcp_tran_timeout, unsigned int tcp_est_timeout)
{
  assert(sr);

  struct sr_nat *nat = sr->nat;
  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, sr);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
  nat->unsol = NULL;
  /* Initialize any variables here */
  nat->icmp_timeout = icmp_timeout;
  nat->tcp_tran_timeout = tcp_tran_timeout;
  nat->tcp_est_timeout = tcp_est_timeout;

  return success;
}

/* Destroys the nat (free memory) */
int sr_nat_destroy(struct sr_nat *nat)
{
  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
  struct sr_nat_mapping *cur_mapping = nat->mappings;
  struct sr_nat_mapping *next_mapping = NULL;
  while(cur_mapping)
  {
    /*Save next mapping so we don't lose it*/
    next_mapping = cur_mapping->next;

    /*Free all connections*/
    struct sr_nat_connection *cur_conn = cur_mapping->conns;
    struct sr_nat_connection *next_conn = NULL;
    while(cur_conn)
    {
      next_conn = cur_conn->next;
      free(cur_conn);
      cur_conn = next_conn;
    }

    /*Free current mapping*/
    free(cur_mapping);
    cur_mapping = next_mapping;
  }

  struct sr_nat_unsol_syn *curr_unsol = nat->unsol;
  struct sr_nat_unsol_syn *next_unsol = NULL;
  while (curr_unsol)
  {
    next_unsol = curr_unsol->next;

    free(curr_unsol->packet);
    free(curr_unsol);

    curr_unsol = next_unsol;
  }

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

/* Periodic Timout handling */
void *sr_nat_timeout(void *sr_ptr)
{
  struct sr_instance *sr = (struct sr_instance *)sr_ptr;
  struct sr_nat *nat = sr->nat;
  while (1) {
    sleep(1.0);

    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* handle periodic tasks here */
    struct sr_nat_mapping *prev = NULL;
    struct sr_nat_mapping *curr = nat->mappings;
    struct sr_nat_mapping *next;
    while(curr)
    {
      next = curr->next;
      if(curr->type == nat_mapping_icmp)
      {
        if (difftime(curtime, curr->last_updated) >= nat->icmp_timeout)
        {
          if(prev == NULL)
          {
            nat->mappings = next;
          }
          else
          {
            prev->next = next;
          }

          free(curr);
          curr = next;
        }
        else
        {
          prev = curr;
          curr = next;
        }
      }
      else
      {
        struct sr_nat_connection *prev_conn = NULL;
        struct sr_nat_connection *curr_conn = curr->conns;
        struct sr_nat_connection *next_conn;

        while(curr_conn)
        {
          next_conn = curr_conn->next;

          if(curr_conn->state == state_estab)
          {
            if(difftime(curtime, curr_conn->last_updated) >= nat->tcp_est_timeout)
            {
              if(prev == NULL)
              {
                curr->conns = next_conn;
              }
              else
              {
                prev_conn->next = next_conn;
              }

              free(curr_conn);
            }
            else
            {
              prev_conn = curr_conn;
            }
          }
          else if(difftime(curtime, curr_conn->last_updated) >= nat->tcp_tran_timeout ||
                  curr_conn->state == state_closed_2)
          {
            if(prev == NULL)
            {
              curr->conns = next_conn;
            }
            else
            {
              prev_conn->next = next_conn;
            }

            free(curr_conn);
          }
          else
          {
            prev_conn = curr_conn;
          }
          curr_conn = next_conn;
        }

        if(curr->conns == NULL)
        {
          if(prev == NULL)
          {
            nat->mappings = next;
          }
          else
          {
            prev = next;
          }

          free(curr);
        }
        else
        {
          prev = curr;
        }

        curr = next;
      }
    }

    struct sr_nat_unsol_syn *prev_unsol = NULL;
    struct sr_nat_unsol_syn *curr_unsol = nat->unsol;
    struct sr_nat_unsol_syn *next_unsol;

    while(curr_unsol)
    {
      next_unsol = curr_unsol->next;

      if(difftime(curtime, curr_unsol->time_received) >= UNSOL_TIMEOUT)
      {
        if(ntohs(curr_unsol->aux_ext) >= 1024)
        {
          sr_send_icmp_packet(sr, curr_unsol->packet, icmp_type_unreachable, icmp_code_port_unreachable);
        }

        if(prev == NULL)
        {
          nat->unsol = next_unsol;
        }
        else
        {
          prev_unsol->next = next_unsol;
        }

        free(curr_unsol->packet);
        free(curr_unsol);

        curr_unsol = next_unsol;
      }
      else if(sr_nat_lookup_external(nat, curr_unsol->aux_ext, nat_mapping_tcp))
      {
        if(prev == NULL)
        {
          nat->unsol = next_unsol;
        }
        else
        {
          prev_unsol->next = next_unsol;
        }

        free(curr_unsol->packet);
        free(curr_unsol);

        curr_unsol = next_unsol;
      }
      else
      {
        prev_unsol = curr_unsol;
        curr_unsol = next_unsol;
      }
    }

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type )
{
  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;

  struct sr_nat_mapping *mapping = nat->mappings;
  while(mapping)
  {
    if(mapping->aux_ext == aux_ext && mapping->type == type)
    {
      copy = malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

      pthread_mutex_unlock(&(nat->lock));
      return copy;
    }

    mapping = mapping->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type )
{
  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;

  struct sr_nat_mapping *mapping = nat->mappings;
  while(mapping)
  {
    if(mapping->aux_int == aux_int && mapping->type == type && mapping->ip_int == ip_int)
    {
      copy = malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

      pthread_mutex_unlock(&(nat->lock));
      return copy;
    }

    mapping = mapping->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint32_t ip_ext, uint16_t aux_int, sr_nat_mapping_type type )
{
  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = malloc(sizeof(struct sr_nat_mapping));
  struct sr_nat_mapping *copy_mapping = malloc(sizeof(struct sr_nat_mapping));
  mapping->type = type;
  mapping->ip_int = ip_int; /* internal ip addr */
  mapping->ip_ext = ip_ext; /* external ip addr */
  mapping->aux_int = aux_int; /* internal port or icmp id */
  mapping->aux_ext = get_available_port(nat); /* GET NEW EXTERNAL PORT/ICMP ID */
  mapping->last_updated = time(NULL); /* use to timeout mappings */
  mapping->conns = NULL; /* list of connections. null for ICMP */

  insert_mapping(nat, mapping);

  memcpy(copy_mapping, mapping, sizeof(struct sr_nat_mapping));

  pthread_mutex_unlock(&(nat->lock));
  return copy_mapping;
}

/************************************************************************
**  get_available_port()
**    struct sr_nat *nat
**        - The NAT instance containing all used port numbers
**
**    Returns an unused port number
************************************************************************/
uint16_t get_available_port(struct sr_nat *nat)
{
  if(nat->mappings == NULL || MIN_PORT_NUMBER < ntohs(nat->mappings->aux_ext))
  {
    return (uint16_t)htons(MIN_PORT_NUMBER);
  }
  else
  {
    struct sr_nat_mapping *curr = nat->mappings;

    while (curr->next != NULL && ntohs(curr->next->aux_ext) - ntohs(curr->aux_ext) == 1)
    {
      curr = curr->next;
    }

    return htons(ntohs(curr->aux_ext) + 1);
  }
}

void insert_mapping(struct sr_nat *nat, struct sr_nat_mapping *mapping)
{
  if(nat->mappings == NULL || ntohs(mapping->aux_ext) < ntohs(nat->mappings->aux_ext))
  {
    mapping->next = nat->mappings;
    nat->mappings = mapping;
  }
  else
  {
    struct sr_nat_mapping *curr = nat->mappings;

    while(curr->next != NULL && ntohs(curr->next->aux_ext) < ntohs(mapping->aux_ext))
    {
      curr = curr->next;
    }

    mapping->next = curr->next;
    curr->next = mapping;
  }
}

void sr_nat_insert_unsol(struct sr_nat *nat, uint8_t *packet, uint16_t aux_ext,
                         unsigned int len)
{
  pthread_mutex_lock(&(nat->lock));

  struct sr_nat_unsol_syn *new_unsol = malloc(sizeof(struct sr_nat_unsol_syn));
  new_unsol->time_received = time(NULL);
  new_unsol->aux_ext = aux_ext;
  new_unsol->packet = malloc(len);
  memcpy(new_unsol->packet, packet, len);

  new_unsol->next = nat->unsol;
  nat->unsol = new_unsol;

  pthread_mutex_unlock(&(nat->lock));
}

void nat_handlepacket(struct sr_instance *sr, uint8_t *packet,
                      unsigned int len, char *interface)
{
  if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))
  {
    printf("IP packet too small and dropped\n");
    return;
  }

  if(strcmp("eth1", interface) == 0)
  {
    nat_handle_internal(sr, packet, len, interface);
  }
  else
  {
    nat_handle_external(sr, packet, len, interface);
  }
}

void nat_handle_internal(struct sr_instance *sr, uint8_t *packet,
                         unsigned int len, char *interface)
{
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  if(cksum(ip_hdr, sizeof(sr_ip_hdr_t)) != 0xffff)
  {
    printf("IP checksum invalid, packet dropped\n");
    return;
  }

  struct sr_nat_mapping *mapping = NULL;

  if(ip_protocol((uint8_t *)ip_hdr) == ip_protocol_tcp)
  {
    sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* Toss if destined for the router */
    if(ip_hdr->ip_dst == sr_get_interface(sr, interface)->ip)
    {
      sr_send_icmp_packet(sr, packet, icmp_type_unreachable, icmp_code_port_unreachable);
      return;
    }

    mapping = sr_nat_lookup_internal(sr->nat, ip_hdr->ip_src, tcp_hdr->tcp_src, nat_mapping_tcp);

    if(mapping == NULL)
    {
      mapping = sr_nat_insert_mapping(sr->nat, ip_hdr->ip_src, sr_get_interface(sr, "eth2")->ip, tcp_hdr->tcp_src, nat_mapping_tcp);
      sr_nat_insert_connection(sr->nat, mapping, ip_hdr->ip_dst, tcp_hdr->tcp_dst);
    }

    /* CHECK/ADD CONN */
    struct sr_nat_connection *conn = nat_connection_lookup(sr->nat, mapping, ip_hdr->ip_dst, tcp_hdr->tcp_dst);
    if(conn == NULL)
    {
      conn = sr_nat_insert_connection(sr->nat, mapping, ip_hdr->ip_dst, tcp_hdr->tcp_dst);
    }

    /* FIX CONN STATE DATA ACCORDING TO PACKET FLAGS */

    /* REWRITE IP/TCP header */
    sr_nat_apply_mapping_internal(mapping, packet, len);

    /* SEND FUCKING PACKET USING sr_forward_ip_packet() */
    sr_forward_ip_packet(sr, packet, len, interface);
  }
  else if(ip_protocol((uint8_t *)ip_hdr) == ip_protocol_icmp)
  {
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* Reply if internal icmp echo requested */
    if(ip_hdr->ip_dst == sr_get_interface(sr, interface)->ip)
    {
      sr_handle_icmp_packet(sr, packet, len, interface);
    }
    /* Needs to be translated and forwarded */
    else
    {
      mapping = sr_nat_lookup_internal(sr->nat, ip_hdr->ip_src, icmp_hdr->icmp_op1, nat_mapping_icmp);

      if(mapping == NULL)
      {
        mapping = sr_nat_insert_mapping(sr->nat, ip_hdr->ip_src, sr_get_interface(sr, "eth2")->ip, icmp_hdr->icmp_op1, nat_mapping_icmp);
      }

      /* NO CONN INFO NEEDED */
      /* FIX HEADER AND SEND THE FUCK OUT USING sr_forward_ip_packet() */
      sr_nat_apply_mapping_internal(mapping, packet, len);

      sr_forward_ip_packet(sr, packet, len, interface);
    }
  }
  else /* UDP packet, drop */
  {
    printf("UDP packet inbound, dropping.");
    sr_send_icmp_packet(sr, packet, icmp_type_unreachable, icmp_code_port_unreachable);
    return;
  }
}

void nat_handle_external(struct sr_instance *sr, uint8_t *packet,
                         unsigned int len, char *interface)
{
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  if(cksum(ip_hdr, sizeof(sr_ip_hdr_t)) != 0xffff)
  {
    printf("IP checksum invalid, packet dropped\n");
    return;
  }

  struct sr_nat_mapping *mapping = NULL;

  if(ip_protocol((uint8_t *)ip_hdr) == ip_protocol_tcp)
  {
    sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(ip_hdr + 1);

    mapping = sr_nat_lookup_external(sr->nat, tcp_hdr->tcp_dst, nat_mapping_tcp);\

    if(mapping == NULL)
    {
        /* CHECK IF SYN */
        if(ntohs(tcp_hdr->tcp_dst) < MIN_PORT_NUMBER)
        {
          sr_handle_ip_packet(sr, packet, len, interface);
        }
        else if(is_flag_type(tcp_hdr, TCP_SYN))
        {
          /* ADD UNSOL SYN TO LIST */
          sr_nat_insert_unsol(sr->nat, packet, tcp_hdr->tcp_dst, len);
        }

        return;
    }

    struct sr_nat_connection *conn = nat_connection_lookup(sr->nat, mapping, ip_hdr->ip_src, tcp_hdr->tcp_src);
    if(conn == NULL)
    {
        /* CREATE CONN */
        sr_nat_insert_connection(sr->nat, mapping, ip_hdr->ip_dst, tcp_hdr->tcp_dst);

        /* UPDATE CONN */
    }

    sr_nat_apply_mapping_external(mapping, packet, len);

    sr_forward_ip_packet(sr, packet, len, interface);
  }
  else if(ip_protocol((uint8_t *)ip_hdr) == ip_protocol_icmp)
  {
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(ip_hdr + 1);

    mapping = sr_nat_lookup_external(sr->nat, icmp_hdr->icmp_op1, nat_mapping_icmp);
    if(mapping == NULL)
    {
        /* DROP PACKET FOR NOW */
        sr_handle_icmp_packet(sr, packet, len, interface);
        return;
    }

    sr_nat_apply_mapping_external(mapping, packet, len);

    sr_forward_ip_packet(sr, packet, len, interface);
  }
  else
  {
    printf("Dropping unknown IP packet\n");
    /*sr_send_icmp_packet(sr, packet, icmp_type_unreachable, icmp_code_port_unreachable);*/
    return;
  }
}

struct sr_nat_connection *sr_nat_insert_connection(struct sr_nat *nat, struct sr_nat_mapping *mapping,
                                                   uint32_t dst_ip, uint16_t dst_port)
{
  pthread_mutex_lock(&(nat->lock));

  struct sr_nat_mapping *curr = nat->mappings;
  while(curr)
  {
    if(curr->type == mapping->type && curr->aux_int == mapping->aux_int)
    {
      break;
    }
    curr = curr->next;
  }

  struct sr_nat_connection *new_conn = malloc(sizeof(struct sr_nat_connection));
  memset(new_conn, 0, sizeof(struct sr_nat_connection));
  struct sr_nat_connection *new_conn_copy = malloc(sizeof(struct sr_nat_connection));
  new_conn->state = state_closed_1;
  new_conn->last_updated = time(NULL);
  new_conn->dst_ip = dst_ip;
  new_conn->dst_port = dst_port;

  new_conn->next = curr->conns;
  curr->conns = new_conn;

  memcpy(new_conn_copy, new_conn, sizeof(struct sr_nat_connection));

  pthread_mutex_unlock(&(nat->lock));

  return new_conn_copy;
}

/* Given a packet from the internal interface, apply external mapping */
void sr_nat_apply_mapping_internal(struct sr_nat_mapping *mapping, uint8_t *packet, unsigned int len)
{
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  ip_hdr->ip_src = mapping->ip_ext;

  if (ip_protocol((uint8_t *)ip_hdr) == ip_protocol_icmp)
  {
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(ip_hdr + 1);
    icmp_hdr->icmp_op1 = mapping->aux_ext;
    icmp_hdr->icmp_sum = 0x0000;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
  }
  else
  { /*TCP*/
    sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(ip_hdr + 1);
    tcp_hdr->tcp_src = mapping->aux_ext;
    tcp_hdr->tcp_sum = 0x0000;
    tcp_hdr->tcp_sum = tcp_cksum(packet, len);
  }
  /*recalculate checksum*/
  ip_hdr->ip_sum = 0x0000;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
}


/* Given a packet from the external interface, apply internal mapping */
void sr_nat_apply_mapping_external(struct sr_nat_mapping *mapping, uint8_t *packet, unsigned int len)
{
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  ip_hdr->ip_dst = mapping->ip_int;

  if (ip_protocol((uint8_t *)ip_hdr) == ip_protocol_icmp)
  {
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(ip_hdr + 1);
    icmp_hdr->icmp_op1 = mapping -> aux_int;
    icmp_hdr->icmp_sum = 0x0000;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));
  }
  else
  { /*TCP*/
    sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(ip_hdr + 1);
    tcp_hdr->tcp_dst = mapping->aux_int;
    tcp_hdr->tcp_sum = 0x0000;
    tcp_hdr->tcp_sum = tcp_cksum(packet, len);
  }
  /*recalculate checksum*/
  ip_hdr->ip_sum = 0x0000;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
}


/* Takes a mapping and searches for a connection using destination ip
   If not conn found, returns null.*/
struct sr_nat_connection *nat_connection_lookup(struct sr_nat *nat, struct sr_nat_mapping *mapping,
                                                uint32_t dst_ip, uint16_t dst_port)
{
  pthread_mutex_lock(&(nat->lock));

  struct sr_nat_connection *copy = NULL;

  struct sr_nat_connection *connection = mapping->conns;
  while(connection)
  {
    if(connection->dst_ip == dst_ip && connection->dst_port == dst_port)
    {
      copy = malloc(sizeof(struct sr_nat_connection));
      memcpy(copy, connection, sizeof(struct sr_nat_connection));

      pthread_mutex_unlock(&(nat->lock));
      return copy;
    }

    connection = connection->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

int is_flag(sr_tcp_hdr_t *tcp_hdr)
{
  if (tcp_hdr->tcp_flags & TCP_FIN || tcp_hdr->tcp_flags & TCP_SYN ||
      tcp_hdr->tcp_flags & TCP_RST || tcp_hdr->tcp_flags & TCP_PSH ||
      tcp_hdr->tcp_flags & TCP_ACK || tcp_hdr->tcp_flags & TCP_URG ||
      tcp_hdr->tcp_flags & TCP_ECE || tcp_hdr->tcp_flags & TCP_CWR)
  {
    return 1;
  }

  return 0;
}

int is_flag_type(sr_tcp_hdr_t *tcp_hdr, uint8_t flag)
{
  return (tcp_hdr->tcp_flags & flag) > 0;
}

/* Return 1 if can not update and packet needs to be dropped */
int update_conn(struct sr_nat_mapping *mapping, struct sr_nat_connection *connection,
                sr_tcp_hdr_t *tcp_hdr, sr_nat_incoming incoming)
{
  struct sr_nat_connection *conn = mapping->conns;

  while(conn->state != connection->state && conn->dst_port != connection->dst_port)
  {
    conn = conn->next;
  }

  conn->last_updated = time(NULL);

  if(is_flag_type(tcp_hdr, TCP_RST))
  {
    conn->state = state_closed_2;
    return 0;
  }

  switch(conn->state)
  {
    case state_closed_1:
      if(is_flag_type(tcp_hdr, TCP_SYN) && incoming == nat_internal)
      {
        conn->state = state_syn_sent;
        return 0;
      }
      break;
    case state_syn_sent:
      if(is_flag_type(tcp_hdr, TCP_SYN) && is_flag_type(tcp_hdr, TCP_ACK) && incoming == nat_external)
      {
        conn->state = state_estab;
        return 0;
      }
      if(is_flag_type(tcp_hdr, TCP_SYN) && incoming == nat_external)
      {
        conn->state = state_syn_rcvd;
        return 0;
      }
      break;
    case state_syn_rcvd:
      if(is_flag_type(tcp_hdr, TCP_ACK) && incoming == nat_external)
      {
        conn->state = state_estab;
        return 0;
      }
      if(is_flag_type(tcp_hdr, TCP_FIN) && incoming == nat_internal)
      {
        conn->state = state_fin_wait_1;
        return 0;
      }
      if (is_flag_type(tcp_hdr, TCP_ACK) && incoming == nat_internal)
      {
        return 0;
      }
      break;
    case state_estab:
      if(is_flag_type(tcp_hdr, TCP_ACK) && incoming == nat_external)
      {
        return 0;
      }
      if(is_flag_type(tcp_hdr, TCP_ACK) && incoming == nat_internal)
      {
        return 0;
      }
      if(is_flag_type(tcp_hdr, TCP_FIN) && incoming == nat_internal)
      {
        conn->state = state_fin_wait_1;
        return 0;
      }
      if(is_flag_type(tcp_hdr, TCP_FIN) && incoming == nat_external)
      {
        conn->state = state_close_wait;
        return 0;
      }
      break;
    case state_fin_wait_1:
      if(is_flag_type(tcp_hdr, TCP_FIN) && incoming == nat_internal)
      {
        return 0;
      }
      if (is_flag_type(tcp_hdr, TCP_ACK) && incoming == nat_external)
      {
        conn->state = state_fin_wait_2;
        return 0;
      }
      if (is_flag_type(tcp_hdr, TCP_FIN) && incoming == nat_external)
      {
        conn->state = state_closing;
        return 0;
      }
      break;
    case state_fin_wait_2:
      if (is_flag_type(tcp_hdr, TCP_FIN) && incoming == nat_external)
      {
        conn->state = state_time_wait;
        return 0;
      }
      break;
    case state_closing:
      if (is_flag_type(tcp_hdr, TCP_ACK) && incoming == nat_internal)
      {
        return 0;
      }
      if (is_flag_type(tcp_hdr, TCP_ACK) && incoming == nat_external)
      {
        conn->state = state_time_wait;
        return 0;
      }
      break;
    case state_close_wait:
      if (is_flag_type(tcp_hdr, TCP_ACK) && incoming = nat_internal)
      {
        return 0;
      }
      if (is_flag_type(tcp_hdr, TCP_FIN) && incoming == nat_internal)
      {
        conn->state = state_last_ack;
        return 0;
      }
      break;
    case state_last_ack:
      if (is_flag_type(tcp_hdr, TCP_FIN) && incoming == nat_internal)
      {
        return 0;
      }
      if (is_flag_type(tcp_hdr, TCP_ACK) && incoming == nat_external)
      {
        //ASK SHAWN ABOUT RECEIVING ACK OF FIN AND CHANGING TO CLOSED
        return 0;
      }
      break;
    case state_time_wait:
      if (is_flag_type(tcp_hdr, TCP_ACK) && incoming == nat_internal)
      {
        return 0;
      }
      // ASK SHAWN ABOUT TIMEOUT=2MSL
      break;
  }

  return 1;
}
