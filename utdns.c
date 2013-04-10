#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <syslog.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>     // inet_addr()


// maximum number of concurrent transactions
#define MAX_TRX 512
// timeout [s] after which a stale transaction is removed
#define TIMEOUT 10


#define LOG_WARN LOG_WARNING
#define FRAMESIZE 65536
#define NOBODY 65534


typedef struct dns_trx
{
   struct sockaddr_storage addr;
   socklen_t addr_len;
   time_t time;
   int dst_sock;
   int data_len;
   char data[FRAMESIZE + 2];
} dns_trx_t;


void log_msg(int, const char*, ...) __attribute__((format (printf, 2, 3)));


static const char *dns_rr_type(int type)
{
   switch (type)
   {
      case 1:
         return "A";

      case 28:
         return "AAAA";

      case 5:
         return "CNAME";

      case 2:
         return "NS";

      case 12:
         return "PTR";

      case 6:
         return "SOA";

      case 15:
         return "MX";

      case 0xff:
         return "ANY";

      default:
         return "(tbd)";
   }
}


static int dns_label_to_buf(const char *src, char *buf, int len)
{
   int i, llen;

   llen = *src++;
   for (i = 0, len--; i < llen && len > 0; i++, src++, len--, buf++)
      *buf = *src;
   *buf = '\0';
   return i;
}


static int dns_name_to_buf(const char *src, char *buf, int len)
{
   int llen, nlen;

   for (nlen = 0;;src += llen + 1)
   {
      if (!(llen = dns_label_to_buf(src, buf, len)))
         break;
      buf += llen;
      *buf = '.';
      buf++;
      len -= llen + 1;
      nlen += llen + 1;
   }
   return nlen + 1;
}


static int init_udp_socket(int port)
{
   struct sockaddr_in6 udp6_addr;
   int sock;

   memset(&udp6_addr, 0, sizeof(udp6_addr));
   udp6_addr.sin6_family = AF_INET6;
   udp6_addr.sin6_port = htons(port);
   //udp6_addr.sin6_addr = in6addr_loopback;

   if ((sock = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0)) == -1)
   {
      log_msg(LOG_ERR, "creating udp socket failed: %s", strerror(errno));
      return -1;
   }

   if (bind(sock, (struct sockaddr*) &udp6_addr, sizeof(udp6_addr)) == -1)
   {
      log_msg(LOG_ERR, "binding udp socket failed: %s", strerror(errno));
      (void) close(sock);
      return -1;
   }

   return sock;
}


static void log_udp_in(const dns_trx_t *dt)
{
   char buf[64], name[256];
   int len, qtype;

   if (getnameinfo((struct sockaddr*) &dt->addr, dt->addr_len, buf, sizeof(buf), NULL, 0, NI_NUMERICHOST))
      return;

   len = dns_name_to_buf(dt->data + 14, name, sizeof(name));
   qtype = ntohs(*((int16_t*) (dt->data + 14 + len)));
   log_msg(LOG_INFO, "%d bytes incoming from %s, '%s'/%s", dt->data_len, buf, name, dns_rr_type(qtype));
}


static int connect_to_dns_server(const struct sockaddr *dns_addr, socklen_t addr_len)
{
   int sock;

   if ((sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) == -1)
   {
      log_msg(LOG_ERR, "creating tcp socket for NS connection failed: %s", strerror(errno));
      return -1;
   }

   if (connect(sock, dns_addr, addr_len) == -1 &&
         errno != EINPROGRESS)
   {
      log_msg(LOG_ERR, "async connect to NS connection failed: %s", strerror(errno));
      (void) close(sock);
      return -1;
   }

   log_msg(LOG_INFO, "connecting %d to NS", sock);
   return sock;
}


static int send_to_dns(dns_trx_t *trx)
{
   int len;

   if ((len = send(trx->dst_sock, trx->data, trx->data_len, 0)) == -1)
   {
      log_msg(LOG_ERR, "sending data on %d to NS failed: %s", trx->dst_sock, strerror(errno));
      return -1;
   }
   log_msg(LOG_INFO, "sending data to NS on %d", trx->dst_sock);
   
   if (len < trx->data_len)
   {
      log_msg(LOG_ERR, "tcp send truncated: sent %d/%d", len, trx->data_len);
      memmove(trx->data, trx->data + len, trx->data_len - len);
   }
   trx->data_len -= len;
   return len;
}


static dns_trx_t *get_free_trx(dns_trx_t *trx, int trx_cnt)
{
   for (; trx_cnt; trx_cnt--, trx++)
      if (trx->dst_sock <= 0)
         return trx;
   return NULL;
}


static int dispatch_packets(int udp_sock, dns_trx_t *trx, int trx_cnt, const struct sockaddr *dns_addr, socklen_t addr_len)
{
   int i, nfds, len, so_err;
   socklen_t so_err_len;
   fd_set rset, wset;
   dns_trx_t *inp;
   time_t curr;

   for (;;)
   {
      FD_ZERO(&rset);
      FD_ZERO(&wset);

      // wait on udp socket for input packets
      FD_SET(udp_sock, &rset);
      nfds = udp_sock;

      curr = time(NULL);
      for (i = 0; i < trx_cnt; i++)
      {
         if (trx[i].dst_sock <= 0)
            continue;

         if (trx[i].time < curr - TIMEOUT)
         {
            log_msg(LOG_NOTICE, "removing stale socket %d", trx[i].dst_sock);
            (void) close(trx[i].dst_sock);
            trx[i].dst_sock = 0;
            continue;
         }

         // data is waiting for sending to NS
         if (trx[i].data_len)
         {
            log_msg(LOG_INFO, "adding %d to wset", trx[i].dst_sock);
            FD_SET(trx[i].dst_sock, &wset);
         }
         // tcp is ready for reading from NS
         else
         {
            log_msg(LOG_INFO, "adding %d to rset", trx[i].dst_sock);
            FD_SET(trx[i].dst_sock, &rset);
         }

         if (nfds < trx[i].dst_sock)
            nfds = trx[i].dst_sock;
      }

      if ((nfds = select(nfds + 1, &rset, &wset, NULL, NULL)) == -1)
      {
         log_msg(LOG_ERR, "select() failed: %s", strerror(errno));
         return -1;
      }
      log_msg(LOG_INFO, "%d sockets ready", nfds);

      // test for incoming packet on udp
      if (FD_ISSET(udp_sock, &rset))
      {
         nfds--;
         if ((inp = get_free_trx(trx, trx_cnt)) == NULL)
         {
            log_msg(LOG_WARN, "no free trx in table, retrying immediately");
         }
         else
         {
            inp->addr_len = sizeof(inp->addr);
            if ((inp->data_len = recvfrom(udp_sock, &inp->data[2], sizeof(inp->data) - 2, 0,
                     (struct sockaddr*) &inp->addr, &inp->addr_len)) == -1)
            {
               log_msg(LOG_ERR, "recvfrom() on udp socket failed: %s", strerror(errno));
               return -1;
            }

            log_udp_in(inp);

            if ((inp->dst_sock = connect_to_dns_server(dns_addr, addr_len)) == -1)
            {
               log_msg(LOG_ERR, "dropping request");
               inp->data_len = 0;
            }
            else
            {
               // set length header for DNS/TCP
               *((uint16_t*) &inp->data[0]) = htons(inp->data_len);
               inp->data_len += 2;
               inp->time = time(NULL);
            }
         }
      }
      
      // test for incoming data on tcp
      for (i = 0; nfds > 0 && i < trx_cnt; i++)
      {
         if (trx[i].dst_sock <= 0)
            continue;

         // incomming data on tcp socket
         if (FD_ISSET(trx[i].dst_sock, &rset))
         {
            nfds--;
            if ((trx[i].data_len = recv(trx[i].dst_sock, trx[i].data, sizeof(trx[i].data), 0)) == -1)
            {
               log_msg(LOG_ERR, "failed to recv() on tcp socket %d: %s", trx[i].dst_sock, strerror(errno));
               return -1;
            }

            log_msg(LOG_INFO, "received %d bytes on tcp socket %d", trx[i].data_len, trx[i].dst_sock);

            trx[i].data_len -= 2;
            if (trx[i].data_len == ntohs(*((uint16_t*) &trx[i].data[0])))
            {
               (void) close(trx[i].dst_sock);
               trx[i].dst_sock = 0;

               if ((len = sendto(udp_sock, &trx[i].data[2], trx[i].data_len, 0,
                     (struct sockaddr*) &trx[i].addr, trx[i].addr_len)) == -1)
               {
                  log_msg(LOG_ERR, "sendto() on udp failed: %s. dropping data", strerror(errno));
               }
               else
               {
                  log_msg(LOG_INFO, "sent %d/%d bytes on udp", len, trx[i].data_len);
               }
               trx[i].data_len = 0;
            }
            else
            {
               // FIXME: handle better
               log_msg(LOG_ERR, "received truncated packet on tcp %d. expect %d got %d",
                     trx[i].dst_sock, trx[i].data_len, (int) ntohs(*((uint16_t*) &trx[i].data[0])));
            }
         } // if (FD_ISSET(trx[i].dst_sock, &rset))

         // tcp socket is ready for sending
         if (FD_ISSET(trx[i].dst_sock, &wset))
         {
            nfds--;
            so_err_len = sizeof(so_err);
            if (getsockopt(trx[i].dst_sock, SOL_SOCKET, SO_ERROR, &so_err, &so_err_len) == -1)
            {
               log_msg(LOG_ERR, "getsockopt on %d failed: %s. closing.", trx[i].dst_sock, strerror(errno));
               (void) close(trx[i].dst_sock);
               trx[i].dst_sock = 0;
            }
            else if (so_err)
            {
               log_msg(LOG_ERR, "could not connect to NS: SO_ERROR = %d. closing.", so_err);
               (void) close(trx[i].dst_sock);
               trx[i].dst_sock = 0;
            }
            else
            {
               log_msg(LOG_INFO, "socket %d connected", trx[i].dst_sock);
               if (send_to_dns(&trx[i]) == -1)
               {
                  log_msg(LOG_ERR, "dropping data and closing %d", trx[i].dst_sock);
                  (void) close(trx[i].dst_sock);
                  trx[i].dst_sock = 0;
               }
            }
         } //if (FD_ISSET(trx[i].dst_sock, &wset))
      }
   }
}


int main(int argc, char **argv)
{
   struct sockaddr_in in;
   dns_trx_t *trx;
   int udp_sock;

   if (argc < 2)
   {
      fprintf(stderr, "usage: %s <NS ip>\n", argv[0]);
      exit(EXIT_FAILURE);
   }

   // FIXME: this should not be hardcoded
   memset(&in, 0, sizeof(in));
   in.sin_family = AF_INET;
   in.sin_port = htons(53);
   if (!inet_aton(argv[1], &in.sin_addr))
   {
      fprintf(stderr, "could not convert %s to in_addr\n", argv[1]);
      exit(EXIT_FAILURE);
   }

   if ((udp_sock = init_udp_socket(53)) == -1)
      perror("init_udp_socket"), exit(EXIT_FAILURE);

   // drop priviledges if root
   if (!getuid())
   {
      if (setgid(NOBODY) == -1)
         log_msg(LOG_ERR, "setgid() failed: %s", strerror(errno)),
            exit(EXIT_FAILURE);
      if (setuid(NOBODY) == -1)
         log_msg(LOG_ERR, "setuid() failed: %s", strerror(errno)),
            exit(EXIT_FAILURE);
      log_msg(LOG_NOTICE, "priviledges dropped");
   }

   if ((trx = calloc(MAX_TRX, sizeof(*trx))) == NULL)
   {
      perror("calloc");
      (void) close(udp_sock);
      return -1;
   }

   dispatch_packets(udp_sock, trx, MAX_TRX, (struct sockaddr*) &in, sizeof(in));
   close(udp_sock);

   return 0;
}

