/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"
#include "sr_nat.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr, int nat_enabled, unsigned int icmp_timeout,
             unsigned int tcp_tran_timeout, unsigned int tcp_est_timeout)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);

    /* Add initialization code here! */
    sr->nat_enabled = nat_enabled;

    if(nat_enabled == 1)
    {
      sr_nat_init(&sr->nat, icmp_timeout, tcp_tran_timeout, tcp_est_timeout);
    }
} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
                     uint8_t * packet/* lent */,
                     unsigned int len,
                     char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  if(len < sizeof(sr_ethernet_hdr_t))
  {
    printf("Ethernet packet received is too small\n");
    return;
  }

  if(ethertype(packet) == ethertype_arp)
  {
    sr_handle_arp_packet(sr, packet, len, interface);
  }
  else if(ethertype(packet) == ethertype_ip)
  {
    if(sr->nat_enabled == 1)
    {
      nat_handlepacket(sr, packet, len, interface);
    }
    else
    {
      sr_handle_ip_packet(sr, packet, len, interface);
    }
  }
  else
  {
    printf("Unknown packet received and dropped\n");
    return;
  }

}/* end sr_ForwardPacket */

void sr_handle_arp_packet(struct sr_instance *sr,
                       uint8_t *packet,
                       unsigned int len,
                       char *interface)
{
  if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t))
  {
    printf("ARP packet too small and dropped\n");
    return;
  }

  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  if(meant_for_this_router(sr, arp_hdr->ar_tip))
  {
    if(arp_hdr->ar_op == htons(arp_op_reply))
    {
      printf("ARP REPLY COMING IN\n");
      sr_handle_arp_reply(sr, packet, len, interface);
    }
    else if(arp_hdr->ar_op == htons(arp_op_request))
    {
      sr_handle_arp_req(sr, packet, len, interface);
    }
    else
    {
      printf("Uknown ARP opcode given\n");
      return;
    }
  }
  else
  {
    printf("ARP packet not destined for this router\n");
    return;
  }
}/* end sr_handle_arp_packet */

void sr_handle_arp_req(struct sr_instance *sr,
                       uint8_t *packet,
                       unsigned int len,
                       char *interface)
{
  /*Create new packet*/
  unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(struct sr_arp_hdr);
  uint8_t *new_packet = malloc(new_len);
  memset(new_packet, 0, new_len);

  /*Get Interface*/
  struct sr_if *iface = sr_get_interface(sr, interface);

  /*Set ethernet info*/
  sr_ethernet_hdr_t *new_ether_hdr = (sr_ethernet_hdr_t *)new_packet;
  sr_ethernet_hdr_t *old_ether_hdr = (sr_ethernet_hdr_t *)packet;
  memcpy(new_ether_hdr->ether_dhost, old_ether_hdr->ether_shost, ETHER_ADDR_LEN);
  memcpy(new_ether_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  new_ether_hdr->ether_type = htons(ethertype_arp);

  /*Set ARP info*/
  struct sr_arp_hdr *new_arp_hdr = (struct sr_arp_hdr *)(new_packet + sizeof(sr_ethernet_hdr_t));
  struct sr_arp_hdr *old_arp_hdr = (struct sr_arp_hdr *)(packet + sizeof(sr_ethernet_hdr_t));
  new_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
  new_arp_hdr->ar_pro = old_arp_hdr->ar_pro;
  new_arp_hdr->ar_hln = ETHER_ADDR_LEN;
  new_arp_hdr->ar_pln = sizeof(uint32_t);
  new_arp_hdr->ar_op = htons(arp_op_reply);
  memcpy(new_arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
  new_arp_hdr->ar_sip = iface->ip;
  memcpy(new_arp_hdr->ar_tha, old_arp_hdr->ar_sha, ETHER_ADDR_LEN);
  new_arp_hdr->ar_tip = old_arp_hdr->ar_sip;

  /*Send out packet*/
  sr_send_packet(sr, new_packet, new_len, interface);

  /*Free new packet from memory*/
  free(new_packet);
}/* end sr_handle_arp_req */

void sr_send_arp_req(struct sr_instance * sr,
                     uint8_t *packet,
                     unsigned int len,
                     char *interface)
{
  /*Create new packet*/
  unsigned int new_len = sizeof(sr_ethernet_hdr_t) + sizeof(struct sr_arp_hdr);
  uint8_t *new_packet = malloc(new_len);
  memset(new_packet, 0, new_len);

  /*Get Interface*/
  struct sr_if *iface = sr_get_interface(sr, interface);

  sr_ethernet_hdr_t *new_ether_hdr = (sr_ethernet_hdr_t *)new_packet;
  memcpy(new_ether_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  memset(new_ether_hdr->ether_dhost, 0xff, ETHER_ADDR_LEN);
  new_ether_hdr->ether_type = htons(ethertype_arp);

  struct sr_arp_hdr *new_arp_hdr = (struct sr_arp_hdr *)(new_packet + sizeof(sr_ethernet_hdr_t));
  sr_ip_hdr_t *old_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  new_arp_hdr->ar_hrd = htons(arp_hrd_ethernet);
  new_arp_hdr->ar_pro = htons(ethertype_ip);
  new_arp_hdr->ar_hln = ETHER_ADDR_LEN;
  new_arp_hdr->ar_pln = sizeof(uint32_t);
  new_arp_hdr->ar_op = htons(arp_op_request);
  memcpy(new_arp_hdr->ar_sha, iface->addr, ETHER_ADDR_LEN);
  new_arp_hdr->ar_sip = iface->ip;
  memset(new_arp_hdr->ar_tha, 0xff, ETHER_ADDR_LEN);
  new_arp_hdr->ar_tip = old_ip_hdr->ip_dst;

  /*Send out packet*/
  sr_send_packet(sr, new_packet, new_len, interface);

  /*Free new packet from memory*/
  free(new_packet);
}/* end sr_send_arp_req */

void sr_handle_arp_reply(struct sr_instance *sr,
                       uint8_t *packet,
                       unsigned int len,
                       char *interface)
{
  sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)packet;
  sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  printf("INSERTING REPLY INTO CACHE\n");
  struct sr_arpreq *req = sr_arpcache_insert(&(sr->cache), ether_hdr->ether_shost, arp_hdr->ar_sip);

  if(req)
  {
    printf("LOOP THROUGH PACKETS AND FORWARD THEM\n");
    struct sr_packet *packets = req->packets;

    while(packets)
    {
      printf("FORWARDING PACKET");
      sr_forward_ip_packet(sr, packets->buf, packets->len, packets->iface);

      packets = packets->next;
    }

    printf("DESTROY ARP REQ\n");
    sr_arpreq_destroy(&(sr->cache), req);
  }
}/* end sr_handle_arp_reply */

void sr_handle_ip_packet(struct sr_instance *sr,
                       uint8_t *packet,
                       unsigned int len,
                       char *interface)
{
  if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t))
  {
    printf("IP packet too small and dropped\n");
    return;
  }

  sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  if(cksum(ip_hdr, sizeof(sr_ip_hdr_t)) != 0xffff)
  {
    printf("IP checksum invalid, packet dropped\n");
    return;
  }

  if(meant_for_this_router(sr, ip_hdr->ip_dst))
  {
    if(ip_protocol((uint8_t *)ip_hdr) == ip_protocol_icmp)
    {
      sr_handle_icmp_packet(sr, packet, len, interface);
    }
    else
    {
      sr_send_icmp_packet(sr, packet, icmp_type_unreachable, icmp_code_port_unreachable);
    }
  }
  else
  {
    printf("FORWARDING IP PACKET\n");
    sr_forward_ip_packet(sr, packet, len, interface);
  }
}/* end sr_handle_ip_packet */

void sr_forward_ip_packet(struct sr_instance *sr,
                          uint8_t *packet,
                          unsigned int len,
                          char *interface)
{
  sr_ip_hdr_t *old_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

  if(old_ip_hdr->ip_ttl == 1)
  {
    printf("TTL EXPIRED\n");
    sr_send_icmp_packet(sr, packet, icmp_type_time_exceeded, 0);
    return;
  }

  uint8_t *new_packet = malloc(len);
  memset(new_packet, 0, len);
  sr_ethernet_hdr_t *new_ether_hdr = (sr_ethernet_hdr_t *)new_packet;
  sr_ip_hdr_t *new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));

  memcpy((char *)new_ip_hdr + sizeof(sr_ip_hdr_t),
         (char *)old_ip_hdr + sizeof(sr_ip_hdr_t),
         len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

  new_ip_hdr->ip_hl = old_ip_hdr->ip_hl;
  new_ip_hdr->ip_v = old_ip_hdr->ip_v;
  new_ip_hdr->ip_tos = old_ip_hdr->ip_tos;
  new_ip_hdr->ip_len = old_ip_hdr->ip_len;
  new_ip_hdr->ip_id = old_ip_hdr->ip_id;
  new_ip_hdr->ip_off = old_ip_hdr->ip_off;
  new_ip_hdr->ip_ttl = old_ip_hdr->ip_ttl - 1;
  new_ip_hdr->ip_p = old_ip_hdr->ip_p;
  new_ip_hdr->ip_dst = old_ip_hdr->ip_dst;
  new_ip_hdr->ip_src = old_ip_hdr->ip_src;
  new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));


  struct sr_rt *route = rt_lookup(sr, old_ip_hdr->ip_dst);
  if(!route)
  {
    sr_send_icmp_packet(sr, packet, icmp_type_unreachable, icmp_code_net_unreachable);
    printf("No routing table match, dropping packet\n");
    return;
  }

  struct sr_if *iface = sr_get_interface(sr, route->interface);
  memcpy(new_ether_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  new_ether_hdr->ether_type = htons(ethertype_ip);

  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), new_ip_hdr->ip_dst);
  if(arp_entry)
  {
    memcpy(new_ether_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);

    sr_send_packet(sr, new_packet, len, route->interface);

    free(new_packet);
    free(arp_entry);
  }
  else
  {
    /*Add req to cache*/
    memset(new_packet, 0, len);
    memcpy(new_packet, packet, len);

    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), old_ip_hdr->ip_dst, new_packet, len, interface);
    sr_handle_arpreq(sr, req);
  }
} /* end sr_forward_ip_packet */

void sr_handle_icmp_packet(struct sr_instance *sr,
                           uint8_t *packet,
                           unsigned int len,
                           char *interface)
{
  if(len < sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t))
  {
    printf("ICMP packet too small and dropped\n");
    return;
  }

  sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet +
                                              sizeof(sr_ethernet_hdr_t) +
                                              sizeof(sr_ip_hdr_t));

  if(cksum(icmp_hdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t)) != 0xffff)
  {
    printf("ICMP checksum invalid, packet dropped\n");
    return;
  }

  if(icmp_hdr->icmp_type == icmp_type_echoreq)
  {
    sr_send_icmp_packet(sr, packet, icmp_type_echoreply, 0);
  }
  else
  {
    printf("Cannot handle given ICMP type, packet dropped\n");
    return;
  }
}

void sr_send_icmp_packet(struct sr_instance *sr,
                         uint8_t *packet,
                         uint8_t type,
                         uint8_t code)
{
  /*sr_ethernet_hdr_t *old_ether_hdr = (sr_ethernet_hdr_t *)packet;*/
  sr_ip_hdr_t *old_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
  sr_icmp_hdr_t *old_icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

  uint8_t *new_packet = 0;
  sr_ip_hdr_t *new_ip_hdr = 0;
  sr_icmp_hdr_t *new_icmp_hdr = 0;
  unsigned int new_len = 0;

  if(type == icmp_type_echoreply)
  {
    new_len = htons(old_ip_hdr->ip_len) + sizeof(sr_ethernet_hdr_t);
    new_packet = malloc(new_len);
    memset(new_packet, 0, new_len);

    new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
    new_icmp_hdr = (sr_icmp_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    new_icmp_hdr->icmp_type = type;
    new_icmp_hdr->icmp_code = code;
    new_icmp_hdr->icmp_op1 = old_icmp_hdr->icmp_op1;
    new_icmp_hdr->icmp_op2 = old_icmp_hdr->icmp_op2;
    memcpy((char *)new_icmp_hdr + sizeof(sr_icmp_hdr_t),
           (char *)old_icmp_hdr + sizeof(sr_icmp_hdr_t),
           new_len - sizeof(sr_ip_hdr_t) - sizeof(sr_ethernet_hdr_t) - sizeof(sr_icmp_hdr_t));
    new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, new_len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

    new_ip_hdr->ip_hl = old_ip_hdr->ip_hl;
    new_ip_hdr->ip_v = old_ip_hdr->ip_v;
    new_ip_hdr->ip_tos = old_ip_hdr->ip_tos;
    new_ip_hdr->ip_len = htons(new_len - sizeof(sr_ethernet_hdr_t));
    new_ip_hdr->ip_id = old_ip_hdr->ip_id;
    new_ip_hdr->ip_off = htons(IP_DF);
    new_ip_hdr->ip_ttl = 64;
    new_ip_hdr->ip_p = ip_protocol_icmp;
    new_ip_hdr->ip_dst = old_ip_hdr->ip_src;
    new_ip_hdr->ip_src = old_ip_hdr->ip_dst;
    new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));
  }
  else if(type == icmp_type_unreachable || type == icmp_type_time_exceeded)
  {
    /*Do new ICMP shit*/
    new_len = sizeof(sr_ethernet_hdr_t) + (2 * sizeof(sr_ip_hdr_t)) + sizeof(sr_icmp_hdr_t) + 8;

    new_packet = malloc(new_len);
    memset(new_packet, 0, new_len);

    new_ip_hdr = (sr_ip_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t));
    new_icmp_hdr = (sr_icmp_hdr_t *)(new_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    new_icmp_hdr->icmp_type = type;
    new_icmp_hdr->icmp_code = code;

    uint8_t *icmp_old_data = (uint8_t *)(new_icmp_hdr + 1);
    memcpy(icmp_old_data, old_ip_hdr, sizeof(sr_ip_hdr_t) + 8);

    new_icmp_hdr->icmp_sum = cksum(new_icmp_hdr, sizeof(sr_icmp_hdr_t) + sizeof(sr_ip_hdr_t) + 8);

    new_ip_hdr->ip_hl = old_ip_hdr->ip_hl;
    new_ip_hdr->ip_v = old_ip_hdr->ip_v;
    new_ip_hdr->ip_tos = old_ip_hdr->ip_tos;
    new_ip_hdr->ip_len = htons(new_len - sizeof(sr_ethernet_hdr_t));
    new_ip_hdr->ip_id = old_ip_hdr->ip_id;
    new_ip_hdr->ip_off = htons(IP_DF);
    new_ip_hdr->ip_ttl = 64;
    new_ip_hdr->ip_p = ip_protocol_icmp;
    new_ip_hdr->ip_dst = old_ip_hdr->ip_src;
  }

  struct sr_rt *route = rt_lookup(sr, old_ip_hdr->ip_src);
  if(!route)
  {
    sr_send_icmp_packet(sr, packet, icmp_type_unreachable, icmp_code_net_unreachable);
    printf("No routing table match, dropping packet\n");
    return;
  }

  if(meant_for_this_router(sr, old_ip_hdr->ip_dst) && type == icmp_type_unreachable)
  {
    new_ip_hdr->ip_src = old_ip_hdr->ip_dst;
    new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));
  }
  else if(type == icmp_type_unreachable || type == icmp_type_time_exceeded)
  {
    struct sr_if *iface = sr_get_interface(sr, route->interface);
    new_ip_hdr->ip_src = iface->ip;
    new_ip_hdr->ip_sum = cksum(new_ip_hdr, sizeof(sr_ip_hdr_t));
  }

  struct sr_if *iface = sr_get_interface(sr, route->interface);
  sr_ethernet_hdr_t *new_ether_hdr = (sr_ethernet_hdr_t *)new_packet;
  memcpy(new_ether_hdr->ether_shost, iface->addr, ETHER_ADDR_LEN);
  new_ether_hdr->ether_type = htons(ethertype_ip);

  struct sr_arpentry *arp_entry = sr_arpcache_lookup(&(sr->cache), new_ip_hdr->ip_dst);
  if(arp_entry)
  {
    memcpy(new_ether_hdr->ether_dhost, arp_entry->mac, ETHER_ADDR_LEN);

    sr_send_packet(sr, new_packet, new_len, route->interface);

    free(new_packet);
    free(arp_entry);
  }
  else
  {
    /*Add req to cache*/
    struct sr_arpreq *req = sr_arpcache_queuereq(&(sr->cache), new_ip_hdr->ip_dst, new_packet, new_len, route->interface);
    sr_handle_arpreq(sr, req);
  }
}/* end sr_send_icmp_packet */

unsigned int meant_for_this_router(struct sr_instance *sr, uint32_t dest_ip)
{
  struct sr_if *interface = sr->if_list;

  while(interface)
  {
    if(interface->ip == dest_ip)
    {
      return 1;
    }

    interface = interface->next;
  }

  return 0;
}/* end meant_for_this_router */
