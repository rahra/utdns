#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>     // inet_addr()


// maximum number of concurrent transactions
#define MAX_TRX 1024


#define FRAMESIZE 65536


typedef struct dns_trx
{
   struct sockaddr_storage addr;
   socklen_t addr_len;
   int dst_sock;
   int data_len;
   char data[FRAMESIZE + 2];
} dns_trx_t;


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
      perror("socket");
      return -1;
   }

   if (bind(sock, (struct sockaddr*) &udp6_addr, sizeof(udp6_addr)) == -1)
   {
      perror("bind");
      (void) close(sock);
      return -1;
   }

   return sock;
}


static void log_udp_in(const dns_trx_t *dt)
{
   char buf[64];

   if (getnameinfo((struct sockaddr*) &dt->addr, dt->addr_len, buf, sizeof(buf), NULL, 0, NI_NUMERICHOST))
      return;

   printf("%d bytes incoming from %s\n", dt->data_len, buf);
}


static int connect_to_dns_server(void)
{
   struct sockaddr_in in;
   int sock;

   if ((sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
   {
      perror("socket(SOCK_STREAM)");
      return -1;
   }

   // FIXME: this should not be hardcoded
   memset(&in, 0, sizeof(in));
   in.sin_family = AF_INET;
   in.sin_port = htons(53);
   in.sin_addr.s_addr = inet_addr("81.94.51.50");

   if (connect(sock, (struct sockaddr*) &in, sizeof(in)) == -1)
   {
      (void) close(sock);
      return -1;
   }

   return sock;
}


static int send_to_dns(dns_trx_t *trx)
{
   int len;

   if ((len = send(trx->dst_sock, trx->data, trx->data_len, 0)) == -1)
   {
      perror("send(dst_sock)");
      return -1;
   }
   
   if (len < trx->data_len)
   {
      fprintf(stderr, "tcp send truncated: sent %d/%d\n", len, trx->data_len);
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


static int dispatch_packets(int udp_sock, dns_trx_t *trx, int trx_cnt)
{
   int i, nfds, len;
   dns_trx_t *inp;
   fd_set rset;

   for (;;)
   {
      FD_ZERO(&rset);
      FD_SET(udp_sock, &rset);
      nfds = udp_sock;

      for (i = 0; i < trx_cnt; i++)
      {
         if (trx[i].dst_sock <= 0)
            continue;

         FD_SET(trx[i].dst_sock, &rset);
         if (nfds < trx[i].dst_sock)
            nfds = trx[i].dst_sock;
      }

      if ((nfds = select(nfds + 1, &rset, NULL, NULL, NULL)) == -1)
      {
         perror("select");
         return -1;
      }

      if (FD_ISSET(udp_sock, &rset))
      {
         // FIXME: NULL value should be handled better
         if ((inp = get_free_trx(trx, trx_cnt)) == NULL)
         {
            fprintf(stderr, "no free trx in tabled\n");
            return -1;
         }

         inp->addr_len = sizeof(inp->addr);
         if ((inp->data_len = recvfrom(udp_sock, &inp->data[2], sizeof(inp->data) - 2, 0,
                     (struct sockaddr*) &inp->addr, &inp->addr_len)) == -1)
         {
            perror("recvfrom");
            return -1;
         }

         log_udp_in(inp);

         // FIXME: error handling shall be improved
         if ((inp->dst_sock = connect_to_dns_server()) == -1)
         {
            fprintf(stderr, "failed to connect to dns\n");
            return -1;
         }

         // set length header for DNS/TCP
         *((uint16_t*) &inp->data[0]) = htons(inp->data_len);
         inp->data_len += 2;

         if (send_to_dns(inp) == -1)
         {
            fprintf(stderr, "failed to send data to dns\n");
            return -1;
         }
      }
      
      // FIXME: nfds is not counted
      for (i = 0; i < trx_cnt; i++)
      {
         if (trx[i].dst_sock <= 0)
            continue;

         // incomming data in tcp socket
         if (FD_ISSET(trx[i].dst_sock, &rset))
         {
            if ((trx[i].data_len = recv(trx[i].dst_sock, trx[i].data, sizeof(trx[i].data), 0)) == -1)
            {
               perror("recv");
               return -1;
            }

            printf("received %d bytes on tcp\n", trx[i].data_len);

            trx[i].data_len -= 2;
            if (trx[i].data_len == ntohs(*((uint16_t*) &trx[i].data[0])))
            {
               (void) close(trx[i].dst_sock);
               trx[i].dst_sock = 0;

               len = sendto(udp_sock, &trx[i].data[2], trx[i].data_len, 0,
                     (struct sockaddr*) &trx[i].addr, trx[i].addr_len);
               printf("sent %d bytes back\n", len);
            }
            else
            {
               // FIXME: handle better
               fprintf(stderr, "received truncated packet\n");
            }
         }
      }
   }
}


int main(int argc, char **argv)
{
   dns_trx_t *trx;
   int udp_sock;

   if ((udp_sock = init_udp_socket(53)) == -1)
      perror("init_udp_socket"), exit(EXIT_FAILURE);

   if ((trx = calloc(MAX_TRX, sizeof(*trx))) == NULL)
   {
      perror("calloc");
      (void) close(udp_sock);
      return -1;
   }

   dispatch_packets(udp_sock, trx, MAX_TRX);
   close(udp_sock);

   return 0;
}

