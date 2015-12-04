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

/* Initializes the nat */
int sr_nat_init(struct sr_nat *nat, unsigned int icmp_timeout,
                unsigned int tcp_tran_timeout, unsigned int tcp_est_timeout)
{
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
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  nat->mappings = NULL;
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

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

/* Periodic Timout handling */
void *sr_nat_timeout(void *nat_ptr)
{
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
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
              curr_conn = next_conn;
            }
            else
            {
              prev_conn = curr_conn;
              curr_conn = next_conn;
            }
          }
          else if(difftime(curtime, curr_conn->last_updated) >= nat->tcp_tran_timeout)
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
            curr_conn = next_conn;
          }
          else
          {
            prev_conn = curr_conn;
            curr_conn = next_conn;
          }
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
          curr = next;
        }
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
  if(nat->mappings == NULL || MIN_PORT_NUMBER < nat->mappings->aux_ext)
  {
    return (uint16_t)MIN_PORT_NUMBER;
  }
  else
  {
    struct sr_nat_mapping *curr = nat->mappings;

    while (curr->next != NULL && curr->next->aux_ext - curr->aux_ext == 1)
    {
      curr = curr->next;
    }

    return curr->aux_ext + 1;
  }
}

void insert_mapping(struct sr_nat *nat, struct sr_nat_mapping *mapping)
{
  if(nat->mappings == NULL || mapping->aux_ext < nat->mappings->aux_ext)
  {
    mapping->next = nat->mappings;
    nat->mappings = mapping;
  }
  else
  {
    struct sr_nat_mapping *curr = nat->mappings;

    while(curr->next != NULL && curr->next->aux_ext < mapping->aux_ext)
    {
      curr = curr->next;
    }

    mapping->next = curr->next;
    curr->next = mapping;
  }
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
    printf("INTERNAL PACKET\n");
    nat_handle_internal(sr, packet, len, interface);
  }
  else
  {
    printf("EXTERNAL PACKET\n");
    nat_handle_external(sr, packet, len, interface);
  }
}

void nat_handle_internal(struct sr_instance *sr, uint8_t *packet,
                         unsigned int len, char *interface)
{
  printf("IP HEADER\n");
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  printf("CHECKSUM\n");
  if(cksum(ip_hdr, sizeof(sr_ip_hdr_t)) != 0xffff)
  {
    printf("IP checksum invalid, packet dropped\n");
    return;
  }

  struct sr_nat_mapping *mapping = NULL;

  printf("CHECK PROTOCOL\n");
  if(ip_protocol((uint8_t *)ip_hdr) == ip_protocol_tcp)
  {
    printf("TCP HEADER\n");
    sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* Toss if destined for the router */
    printf("CHECK ROUTER\n");
    if(meant_for_this_router(sr, ip_hdr->ip_dst))
    {
      printf("MEANT FOR THIS ROUTER\n");
      sr_send_icmp_packet(sr, packet, icmp_type_unreachable, icmp_code_port_unreachable);
      return;
    }

    printf("PERFORM MAPPING LOOKUP\n");
    mapping = sr_nat_lookup_internal(sr->nat, ip_hdr->ip_src, tcp_hdr->tcp_src, nat_mapping_tcp);

    if(mapping == NULL)
    {
      printf("CREATE NEW MAPPING\n");
      mapping = sr_nat_insert_mapping(sr->nat, ip_hdr->ip_src, sr_get_interface(sr, "eth2")->ip, tcp_hdr->tcp_src, nat_mapping_tcp);
    }

    /* CHECK/ADD CONN */
    printf("GET CONN\n");
    struct sr_nat_connection *conn = nat_connection_lookup(sr->nat, mapping, ip_hdr->ip_dst, tcp_hdr->tcp_dst);
    if(conn == NULL)
    {
      printf("CREATE CONN\n");
      conn = sr_nat_insert_connection(sr->nat, mapping, ip_hdr->ip_dst, tcp_hdr->tcp_dst);
    }

    /* FIX CONN STATE DATA ACCORDING TO PACKET FLAGS */

    /* REWRITE IP/TCP header */
    printf("APPLY MAPPING\n");
    sr_nat_apply_mapping_internal(mapping, packet);

    /* SEND FUCKING PACKET USING sr_forward_ip_packet() */
    printf("FORWARDING\n");
    sr_forward_ip_packet(sr, packet, len, interface);
  }
  else if(ip_protocol((uint8_t *)ip_hdr) == ip_protocol_icmp)
  {
    printf("ICMP HEADER\n");
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* Reply if internal icmp echo requested */
    printf("CHECKING THIS ROUTER\n");
    /*if(meant_for_this_router(sr, ip_hdr->ip_dst))*/
    if(ip_hdr->ip_dst == sr_get_interface(sr, interface)->ip)
    {
      printf("MEANT FOR THIS ROUTER\n");
      sr_handle_icmp_packet(sr, packet, len, interface);
    }
    /* Needs to be translated and forwarded */
    else
    {
      printf("LOOKUP MAPP\n");
      mapping = sr_nat_lookup_internal(sr->nat, ip_hdr->ip_src, icmp_hdr->icmp_op1, nat_mapping_icmp);

      if(mapping == NULL)
      {
        printf("CREATE MAPPING\n");
        mapping = sr_nat_insert_mapping(sr->nat, ip_hdr->ip_src, sr_get_interface(sr, "eth2")->ip, icmp_hdr->icmp_op1, nat_mapping_tcp);
      }

      /* NO CONN INFO NEEDED */
      /* FIX HEADER AND SEND THE FUCK OUT USING sr_forward_ip_packet() */
      printf("APPLY MAPP\n");
      sr_nat_apply_mapping_internal(mapping, packet);

      printf("SEND SHIT\n");
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
  printf("IP HEADER\n");
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  printf("CHECKSUM\n");
  if(cksum(ip_hdr, sizeof(sr_ip_hdr_t)) != 0xffff)
  {
    printf("IP checksum invalid, packet dropped\n");
    return;
  }

  struct sr_nat_mapping *mapping = NULL;

  printf("CHECK PROTOCOL\n");
  if(ip_protocol((uint8_t *)ip_hdr) == ip_protocol_tcp)
  {
    printf("TCP HEADER\n");
    sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* Toss if destined for the router */
    printf("CHECK ROUTER\n");
    if(meant_for_this_router(sr, ip_hdr->ip_dst))
    {
      printf("MEANT FOR THIS ROUTER\n");
      sr_send_icmp_packet(sr, packet, icmp_type_unreachable, icmp_code_port_unreachable);
      return;
    }

    printf("PERFORM MAPPING LOOKUP\n");
    mapping = sr_nat_lookup_internal(sr->nat, ip_hdr->ip_src, tcp_hdr->tcp_src, nat_mapping_tcp);

    if(mapping == NULL)
    {
      time_t nowtime = time(NULL);

      while (difftime(time(NULL), nowtime) < tcp_unsolicited_timeout) {
        mapping = sr_nat_lookup_internal(sr->nat, ip_hdr->ip_src, tcp_hdr->tcp_src, nat_mapping_tcp);
        if (mapping != NULL)
        {
          break;
        }
      }
      //send port unreachable
      if(mapping == NULL) {
        sr_send_icmp_packet(sr, packet, icmp_type_unreachable, icmp_code_port_unreachable);
      } 
    }

    /* CHECK/ADD CONN */
    printf("GET CONN\n");
    struct sr_nat_connection *conn = nat_connection_lookup(sr->nat, mapping, ip_hdr->ip_dst, tcp_hdr->tcp_dst);
    if(conn == NULL)
    {
      printf("CREATE CONN\n");
      conn = sr_nat_insert_connection(sr->nat, mapping, ip_hdr->ip_dst, tcp_hdr->tcp_dst);
    }

    /* FIX CONN STATE DATA ACCORDING TO PACKET FLAGS */

    /* REWRITE IP/TCP header */
    printf("APPLY MAPPING\n");
    sr_nat_apply_mapping_internal(mapping, packet);

    /* SEND FUCKING PACKET USING sr_forward_ip_packet() */
    printf("FORWARDING\n");
    sr_forward_ip_packet(sr, packet, len, interface);
  }
  else if(ip_protocol((uint8_t *)ip_hdr) == ip_protocol_icmp)
  {
    printf("ICMP HEADER\n");
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    /* Reply if internal icmp echo requested */
    printf("CHECKING THIS ROUTER\n");
    /*if(meant_for_this_router(sr, ip_hdr->ip_dst))*/
    if(ip_hdr->ip_dst == sr_get_interface(sr, interface)->ip)
    {
      printf("MEANT FOR THIS ROUTER\n");
      sr_handle_icmp_packet(sr, packet, len, interface);
    }
    /* Needs to be translated and forwarded */
    else
    {
      printf("LOOKUP MAPP\n");
      mapping = sr_nat_lookup_internal(sr->nat, ip_hdr->ip_src, icmp_hdr->icmp_op1, nat_mapping_icmp);

      if(mapping == NULL)
      {
        time_t nowtime = time(NULL);

        while (difftime(time(NULL), nowtime) < tcp_unsolicited_timeout) {
          mapping = sr_nat_lookup_internal(sr->nat, ip_hdr->ip_src, tcp_hdr->tcp_src, nat_mapping_tcp);
        if (mapping != NULL)
        {
          break;
        }
      }
      //send port unreachable
      if(mapping == NULL) {
        sr_send_icmp_packet(sr, packet, icmp_type_unreachable, icmp_code_port_unreachable);
      } 
      }

      /* NO CONN INFO NEEDED */
      /* FIX HEADER AND SEND THE FUCK OUT USING sr_forward_ip_packet() */
      printf("APPLY MAPP\n");
      sr_nat_apply_mapping_internal(mapping, packet);

      printf("SEND SHIT\n");
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

struct sr_nat_connection *sr_nat_insert_connection(struct sr_nat *nat, struct sr_nat_mapping *mapping,
                                                   uint32_t dst_ip, uint16_t dst_port)
{
  pthread_mutex_lock(&(nat->lock));

  struct sr_nat_connection *new_conn = malloc(sizeof(struct sr_nat_connection));
  struct sr_nat_connection *new_conn_copy = malloc(sizeof(struct sr_nat_connection));
  new_conn->state = state_closed;
  new_conn->last_updated = time(NULL);
  new_conn->dst_ip = dst_ip;
  new_conn->dst_port = dst_port;

  struct sr_nat_mapping *curr = nat->mappings;
  while(curr != mapping)
  {
    curr = curr->next;
  }

  new_conn->next = curr->conns;
  curr->conns = new_conn;

  memcpy(new_conn_copy, new_conn, sizeof(struct sr_nat_connection));

  pthread_mutex_unlock(&(nat->lock));

  return new_conn_copy;
}

/* Given a packet from the internal interface, apply external mapping */
void sr_nat_apply_mapping_internal(struct sr_nat_mapping *mapping, uint8_t *packet)
{
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  ip_hdr->ip_src = mapping->ip_ext;

  if (ip_protocol((uint8_t *)ip_hdr) == ip_protocol_icmp)
  {
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(ip_hdr + 1);
    icmp_hdr->icmp_op1 = mapping->aux_ext;
    icmp_hdr->icmp_sum = 0x0000;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, (ip_hdr->ip_len) - sizeof(ip_hdr));
  }
  else
  { /*TCP*/
    sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(ip_hdr + 1);
    tcp_hdr->tcp_src = mapping->aux_ext;
    tcp_hdr->tcp_sum = 0x0000;
    tcp_hdr->tcp_sum = cksum(tcp_hdr, (ip_hdr->ip_len) - ip_hdr->ip_hl);
  }
  /*recalculate checksum*/
  ip_hdr->ip_sum = 0x0000;
  ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
}


/* Given a packet from the external interface, apply internal mapping */
void sr_nat_apply_mapping_external(struct sr_nat_mapping *mapping, uint8_t *packet)
{
  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  ip_hdr->ip_dst = mapping->ip_int;

  if (ip_protocol((uint8_t *)ip_hdr) == ip_protocol_icmp)
  {
    sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(ip_hdr + 1);
    icmp_hdr->icmp_op1 = mapping -> aux_int;
    icmp_hdr->icmp_sum = 0x0000;
    icmp_hdr->icmp_sum = cksum(icmp_hdr, (ip_hdr->ip_len) - sizeof(ip_hdr));
  }
  else
  { /*TCP*/
    sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(ip_hdr + 1);
    tcp_hdr->tcp_dst = mapping->aux_int;
    tcp_hdr->tcp_sum = 0x0000;
    tcp_hdr->tcp_sum = cksum(tcp_hdr, ip_hdr->ip_len - ip_hdr->ip_hl);
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

  struct sr_nat_mapping *curr = nat->mappings;
  while(curr != mapping)
  {
    curr = curr->next;
  }

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_connection *copy = NULL;

  struct sr_nat_connection *connection = curr->conns;
  while(connection)
  {
    if(connection->dst_ip == dst_ip && connection->dst_port == dst_port)
    {
      copy = malloc(sizeof(struct sr_nat_connection));
      memcpy(copy, connection, sizeof(struct sr_nat_connection));

      pthread_mutex_unlock(&(nat->lock));
      return copy;
    }
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}
