
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
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
  if(mapping->aux_ext < nat->mappings->aux_ext)
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
