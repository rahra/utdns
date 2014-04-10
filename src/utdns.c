/* Copyright 2013 Bernhard R. Fischer, 2048R/5C5FFD47 <bf@abenteuerland.at>
 *
 * This file is part of Utdns.
 *
 * Utdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, version 3 of the License.
 *
 * Utdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Utdns. If not, see <http://www.gnu.org/licenses/>.
 */

/*! Utdns is a DNS protocol translator which turns UDP/DNS to TCP/DNS.
 *  It receives DNS packets on UDP port 53 and forwards them to a DNS server
 *  with TCP. The NS IP address has to be specified as command line argument.
 *  The responses are sent back again. Therefore, Utdns manages an internal
 *  transaction state table. Stale states are timed out after TIMEOUT secondes.
 *  The state table keeps MAX_TRX concurrent transactions.
 *  In order to bind to the privileged port 53, Utdns has to started as root.
 *  It will immediately drop privileges to NOBODY.
 *
 *
 * redirect all outgoing udp:53 traffic to local utdns running on port 5300:
 * iptables -A OUTPUT -t nat -p udp --dport 53 ! -o lo -j DNAT --to-destination 127.0.0.1:5300
 * iptables -A POSTROUTING -t nat -p udp --dport 5300  -j SNAT --to-source 127.0.0.1
 * redirect all incoming traffic
 * iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <syslog.h>
#include <time.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>     // inet_addr()


// maximum number of concurrent transactions
#define MAX_TRX 512
// timeout [s] after which a stale transaction is removed
#define TIMEOUT 10


#define LOG_WARN LOG_WARNING
#define FRAMESIZE 65536
#define NOBODY 65534

#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 0
#define USE_FCNTL
#define SET_NONBLOCK(x) set_nonblock(x)
#else
#define SET_NONBLOCK(x)
#endif


typedef struct dns_trx
{
   struct sockaddr_storage addr;    // keep socket address of original UDP sender
   socklen_t addr_len;
   time_t time;                     // incoming timestamp
   int dst_sock;                    // socket fd of outgoing TCP connection
   int in_sock;                     // socket fd for incoming TCP connection
   int conn_state;                  // state of transaction
   int data_len;                    // data length to send
   char data[FRAMESIZE + 2];        // data
} dns_trx_t;


void log_msg(int, const char*, ...) __attribute__((format (printf, 2, 3)));
FILE *init_log(const char*, int);


enum {CONN_STATE_NA, CONN_STATE_SEND, CONN_STATE_RECV};


/*! This function decodes the RR type and returns a constant string pointer.
 *  @param type Numeric RR type.
 *  @return Pointer to constant string.
 */
static const char *dns_rr_type(int type)
{
   switch (type)
   {
      case 1: return "A";
      case 28: return "AAAA";
      case 5: return "CNAME";
      case 2: return "NS";
      case 12: return "PTR";
      case 6: return "SOA";
      case 15: return "MX";
      case 0xff: return "ANY";
      default: return "(tbd)";
   }
}


static const char *dns_rcode(int code)
{
   switch (code)
   {
      case 0: return "NOERROR";
      case 1: return "FORMERR";
      case 2: return "SERVFAIL";
      case 3: return "NXDOMAIN";
      case 4: return "NOTIMP";
      case 5: return "REFUSED";
      default: return "";
   }
}


/*! Dns_label_to_buf() converts one label of a domain name to a \0-terminated C
 *  character string. Compressed labels (0xc0) are not decompressed but binary
 *  labels (0x40) are decoded. Thus the character string buf may contain \0
 *  bytes. buf will always be \0-terminated.
 *  @param src Pointer to DNS label.
 *  @param buf Pointer to destination buffer.
 *  @param len Total length of buf.
 *  @return Number of bytes copied to buf excluding the terminating \0. Thus,
 *  the total number of bytes copied to buf is always less than len.
 */
static int dns_label_to_buf(const char *src, char *buf, int len)
{
   int i = 0, llen;

   len--;
   llen = *src++ & 0xff;
   // uncompressed label
   if (!(llen & 0xc0))
   {
      for (; i < llen && len > 0; i++, src++, len--, buf++)
         *buf = *src;
   }
   // compressed label
   else if ((llen & 0xc0) == 0xc0)
   {
      if (len > 0)
      {
         *buf++ = '_';
         i++;
         len--;
      }
   }
   // binary label, EDNS0
   else if ((llen & 0xc0) == 0x40)
   {
      llen = *src & 0xff;
      //*buf++ = *src++;
      if (!llen) len = 256;
      llen--;
      llen >>= 3;
      llen++;
      for (; i <= llen && len > 0; i++, src++, len--, buf++)
         *buf = *src;
   }
   *buf = '\0';
   return i;
}


/*! Decodes a domain name consisting of several DNS labels.
 *  @param src Pointer to domain name.
 *  @param buf Pointer to destination buffer.
 *  @param len Total length of buf.
 *  @return The total number of bytes within buf including the terminating \0
 *  which is also the total number of bytes decoded within src.
 */
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


#ifdef USE_FCNTL
static int set_nonblock(int s)
{
   if (fcntl(s, F_SETFL, O_NONBLOCK) == -1)
   {
      log_msg(LOG_ERR, "fcntl() failed: %s", strerror(errno));
      return -1;
   }
   return 0;
}
#endif


/*! This function opens a UDP socket on all addresses (0.0.0.0 and ::) of the
 * host at the given port number.
 * @param port Port number for the UDP socket.
 * @return Returns a valid file descriptor of the socket or -1 in case of
 * error.
 */
static int init_srv_socket(int family, int type, int port)
{
   struct sockaddr_storage sock_addr;
   int sock, len;

   memset(&sock_addr, 0, sizeof(sock_addr));
   sock_addr.ss_family = family;

   switch (family)
   {
      case AF_INET6:
        ((struct sockaddr_in6*) &sock_addr)->sin6_port = htons(port);
        len = sizeof(struct sockaddr_in6);
         break;

      case AF_INET:
        ((struct sockaddr_in*) &sock_addr)->sin_port = htons(port);
        len = sizeof(struct sockaddr_in);
         break;

      default:
         log_msg(LOG_ERR, "ill address family 0x%04x", family);
         return -1;
   }

   if ((sock = socket(family, type | SOCK_NONBLOCK, 0)) == -1)
   {
      log_msg(LOG_ERR, "creating udp socket failed: %s", strerror(errno));
      return -1;
   }

   SET_NONBLOCK(sock);

   if (bind(sock, (struct sockaddr*) &sock_addr, len) == -1)
   {
      log_msg(LOG_ERR, "binding udp socket failed: %s", strerror(errno));
      (void) close(sock);
      return -1;
   }

   return sock;
}


static int init_tcp_socket(int family, int port)
{
   int s;
   
   if ((s = init_srv_socket(family, SOCK_STREAM, port)) == -1)
      return -1;

   if (listen(s, 10) == -1)
   {
      log_msg(LOG_ERR, "failed to listen(%d): %s", s, strerror(errno));
      close(s);
      return -1;
   }

   return s;
}


static int init_udp_socket(int family, int port)
{
   return init_srv_socket(family, SOCK_DGRAM, port);
}


/*! Simple logging function which outputs some information about a (newly
 * created) DNS transaction.
 * @param dt Pointer to the transaction.
 */
static void log_udp_in(const dns_trx_t *dt)
{
   char buf[64], name[256];
   int len, qtype;

   if (getnameinfo((struct sockaddr*) &dt->addr, dt->addr_len, buf, sizeof(buf), NULL, 0, NI_NUMERICHOST))
      return;

   len = dns_name_to_buf(dt->data + 14, name, sizeof(name));
   qtype = ntohs(*((int16_t*) (dt->data + 14 + len)));
   log_msg(LOG_INFO, "%d bytes incoming from %s, id = 0x%04x, '%s'/%s", dt->data_len, buf, 
         (int) ntohs(*((int16_t*) (dt->data + 2))), name, dns_rr_type(qtype));
}


/*! Asynchronously (non-blocking) open a TCP session to a given destination.
 *  @param dns_addr Destinationa address.
 *  @param addr_len Length of dns_addr structure.
 *  @return Returns a valid file descriptor of the socket being in connection
 *  setup or -1 in case of error.
 */
static int connect_to_dns_server(const struct sockaddr *dns_addr, socklen_t addr_len)
{
   int sock;

   if ((sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) == -1)
   {
      log_msg(LOG_ERR, "creating tcp socket for NS connection failed: %s", strerror(errno));
      return -1;
   }

   SET_NONBLOCK(sock);

   if (connect(sock, dns_addr, addr_len) == -1 &&
         errno != EINPROGRESS)
   {
      log_msg(LOG_ERR, "async connect to NS connection failed: %s", strerror(errno));
      (void) close(sock);
      return -1;
   }

   log_msg(LOG_DEBUG, "connecting %d to NS", sock);
   return sock;
}


/*! Send data to remote NS on an open TCP session.
 *  @param trx Pointer to DNS transaction structure containing the data.
 *  @return Returns the number of bytes sent. The function can be called
 *  several times until the whole data buffer is empty. If all bytes could be
 *  sent the connection state of the transaction (trx->conn_state) is changed
 *  to CONN_STATE_RECV.
 */
static int send_to_dns(dns_trx_t *trx)
{
   int len;

   if ((len = send(trx->dst_sock, trx->data, trx->data_len, 0)) == -1)
   {
      log_msg(LOG_ERR, "sending data on %d to NS failed: %s", trx->dst_sock, strerror(errno));
      return -1;
   }
   log_msg(LOG_DEBUG, "sending data to NS on %d", trx->dst_sock);
   
   if (len < trx->data_len)
   {
      // FIXME: LOG_WARN?
      log_msg(LOG_WARN, "tcp send truncated: sent %d/%d", len, trx->data_len);
      memmove(trx->data, trx->data + len, trx->data_len - len);
   }
   // if all data was sent bump state to RECV
   else
      trx->conn_state = CONN_STATE_RECV;
   trx->data_len -= len;
   return len;
}


/*! Get_free_trx() looks up and returns a pointer to a currently unused
 *  transaction structure within the table of transactions.
 *  @param trx Pointer to the beginning of the transaction table.
 *  @param trx_cnt Number of entries in the table.
 *  @return Returns a valid pointer or NULL of no entry is available. The
 *  connection state of an empty transaction is initialized to CONN_STATE_NA
 *  and the destination (TCP) file descriptor contains a value of less than or
 *  equal to 0.
 */
static dns_trx_t *get_free_trx(dns_trx_t *trx, int trx_cnt)
{
   for (; trx_cnt; trx_cnt--, trx++)
      if (trx->dst_sock <= 0)
      {
         trx->conn_state = CONN_STATE_NA;
         return trx;
      }
   return NULL;
}


/*! This is the main routing for dispatching packets between UDP clients and
 * the TCP name server. It keeps track on all transactions within the
 * transaction table. Stale transactions will be removed not before the timeout
 * (TIMEOUT) elapses.
 * @param udp_sock File descriptor of UDP socket used for receiving packets of
 * the clients.
 * @param trx Pointer to the beginning of the transaction table.
 * @param trx_cnt Number of maximum entries in trx.
 * @param dns_addr Pointer to the socket address of the remote NS.
 * @param addr_len Length of the dns_addr structure.
 * @return -1 in case of error.
 */
static int dispatch_packets(int udp_sock, int tcp_sock, dns_trx_t *trx, int trx_cnt, const struct sockaddr *dns_addr, socklen_t addr_len)
{
   int i, nfds, len, so_err, running = 1;
   socklen_t so_err_len;
   fd_set rset, wset;
   dns_trx_t *inp;
   time_t curr;

   while (running)
   {
      FD_ZERO(&rset);
      FD_ZERO(&wset);

      // wait on udp socket for input packets
      FD_SET(udp_sock, &rset);
      FD_SET(tcp_sock, &rset);
      nfds = udp_sock > tcp_sock ? udp_sock : tcp_sock;

      curr = time(NULL);
      for (i = 0, len = 1; i < trx_cnt; i++)
      {
         // FIXME: an 'active' trx counter would improve execution speed
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
         if (trx[i].conn_state == CONN_STATE_SEND)
         {
            log_msg(LOG_DEBUG, "adding %d to wset", trx[i].dst_sock);
            FD_SET(trx[i].dst_sock, &wset);
            len++;
         }
         // tcp is ready for reading from NS
         else if (trx[i].conn_state == CONN_STATE_RECV)
         {
            log_msg(LOG_DEBUG, "adding %d to rset", trx[i].dst_sock);
            FD_SET(trx[i].dst_sock, &rset);
            len++;
         }
         else
         {
            log_msg(LOG_EMERG, "this should not happen: conn_state = %d", trx[i].conn_state);
            continue;
         }

         if (nfds < trx[i].dst_sock)
            nfds = trx[i].dst_sock;
      } // for (i = 0, len = 0; i < trx_cnt; i++)

      log_msg(LOG_DEBUG, "select()ing on %d sockets", len);
      if ((nfds = select(nfds + 1, &rset, &wset, NULL, NULL)) == -1)
      {
         log_msg(LOG_ERR, "select() failed: %s", strerror(errno));
         return -1;
      }
      log_msg(LOG_DEBUG, "%d sockets ready", nfds);

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

            if (inp->data_len >= 12)
            {
               // FIXME: it should be checked if there is at least 1 question
               log_udp_in(inp);
               if ((inp->dst_sock = connect_to_dns_server(dns_addr, addr_len)) == -1)
               {
                  log_msg(LOG_WARN, "dropping request");
                  inp->data_len = 0;
               }
               else
               {
                  inp->conn_state = CONN_STATE_SEND;
                  // set length header for DNS/TCP
                  *((uint16_t*) &inp->data[0]) = htons(inp->data_len);
                  inp->data_len += 2;
                  inp->time = time(NULL);
               }
            }
            else
               log_msg(LOG_WARN, "ignoring short datagram (len = %d)", inp->data_len);
         }
      } // if (FD_ISSET(udp_sock, &rset))
      
      // check if new incoming tcp session
      if (FD_ISSET(tcp_sock, &rset))
      {
         nfds--;
         if ((inp = get_free_trx(trx, trx_cnt)) == NULL)
         {
            log_msg(LOG_WARN, "no free trx in table, retrying immediately");
         }
         else
         {
            if ((inp->in_sock = accept(tcp_sock, (struct sockaddr*) &inp->addr, &inp->addr_len)) == -1)
               log_msg(LOG_ERR, "accept(%d) failed: %s", tcp_sock, strerror(errno));

            log_msg(LOG_INFO, "accepted new session on %d", inp->in_sock);
            // FIXME: incoming tcp not finished!
         }
      } // if (FD_ISSET(tcp_sock, &rset))

      // test for incoming data on tcp
      for (i = 0; nfds > 0 && i < trx_cnt; i++)
      {
         if (trx[i].dst_sock <= 0)
            continue;

         // incomming data on tcp socket
         if (FD_ISSET(trx[i].dst_sock, &rset))
         {
            nfds--;
            if ((len = recv(trx[i].dst_sock, trx[i].data + trx[i].data_len, sizeof(trx[i].data) - trx[i].data_len, 0)) == -1)
            {
               log_msg(LOG_ERR, "failed to recv() on tcp socket %d: %s. Dropping", trx[i].dst_sock, strerror(errno));
               (void) close(trx[i].dst_sock);
               trx[i].dst_sock = 0;
               continue;
            }

            trx[i].data_len += len;
            log_msg(LOG_DEBUG, "received %d bytes on tcp socket %d", len, trx[i].dst_sock);

            if (trx[i].data_len - 2 == ntohs(*((uint16_t*) &trx[i].data[0])))
            {
               trx[i].data_len -= 2;
               (void) close(trx[i].dst_sock);
               trx[i].dst_sock = 0;

               // FIXME: this should be implemented asynchronous as well
               if ((len = sendto(udp_sock, &trx[i].data[2], trx[i].data_len, 0,
                     (struct sockaddr*) &trx[i].addr, trx[i].addr_len)) == -1)
               {
                  log_msg(LOG_ERR, "sendto() on udp failed: %s. dropping data", strerror(errno));
               }
               else
               {
                  log_msg(LOG_INFO, "replied %d/%d bytes on udp, id = 0x%04x, RCODE = %s", len, trx[i].data_len,
                        (int) ntohs(*((int16_t*) (trx[i].data + 2))), dns_rcode(trx[i].data[5] & 15));
               }
               trx[i].data_len = 0;
            }
            else
            {
               // FIXME: handle better
               log_msg(LOG_NOTICE, "received truncated packet on tcp %d. expect %d got %d, waiting",
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
               log_msg(LOG_DEBUG, "socket %d connected", trx[i].dst_sock);
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
   return 0;
}



//#define TEST_UTDNS_FUNC
#ifdef TEST_UTDNS_FUNC
void test_utdns_func(void)
{
   char testar[] = {0x41, 24, 'a', 'b', 'c', 0xc0, 'A', 3, 'd', 'e', 'f', 0};
   char buf[256];

   dns_name_to_buf(testar, buf, sizeof(buf));
   printf("%s\n", buf);
   exit(0);
}
#endif


static void background(void)
{
   pid_t pid, ppid;

   log_msg(LOG_DEBUG, "backgrounding");

   ppid = getpid();
   pid = fork();
   switch(pid)
   {
      case -1:
         log_msg(LOG_ERR, "fork failed: %s. Staying in foreground", strerror(errno));
         return;

      case 0:
         log_msg(LOG_INFO, "process backgrounded by parent %d, new pid = %d", ppid, getpid());
         (void) umask(0);
         if (setsid() == -1)
            log_msg(LOG_ERR, "could not set process group ID: \"%s\"", strerror(errno));
         if (chdir("/") == -1)
            log_msg(LOG_ERR, "could not change directory to /: \"%s\"", strerror(errno));
         // redirect standard files to /dev/null
         if (!freopen( "/dev/null", "r", stdin))
            log_msg(LOG_ERR, "could not reconnect stdin to /dev/null: \"%s\"", strerror(errno));
         if (!freopen( "/dev/null", "w", stdout))
            log_msg(LOG_ERR, "could not reconnect stdout to /dev/null: \"%s\"", strerror(errno));
         if (!freopen( "/dev/null", "w", stderr))
            log_msg(LOG_ERR, "could not reconnect stderr to /dev/null: \"%s\"", strerror(errno));
         return;

      default:
         log_msg(LOG_DEBUG, "parent %d exits, background pid = %d", ppid, pid);
         exit(EXIT_SUCCESS);
   }
}


static void drop_privileges(void)
{
   if (getuid())
      return;

   // drop priviledges if root
   if (setgid(NOBODY) == -1)
      log_msg(LOG_ERR, "setgid() failed: %s", strerror(errno)),
         exit(EXIT_FAILURE);
   if (setuid(NOBODY) == -1)
      log_msg(LOG_ERR, "setuid() failed: %s", strerror(errno)),
         exit(EXIT_FAILURE);
   log_msg(LOG_NOTICE, "privileges dropped");
}


static void usage(const char *argv0)
{
   printf(
         "UDP/DNS-to-TCP/DNS-Translator V1.0, (c) 2013, Bernhard R. Fischer, 2048R/5C5FFD47 <bf@abenteuerland.at>.\n"
         "Usage: %s [OPTIONS] <NS ip>\n"
         "   -4 .......... Bind to IPv4 only instead of IP + IPv6.\n"
         "   -b .......... Background process and log to syslog.\n"
         "   -d .......... Set log level to LOG_DEBUG.\n"
         "   -p <port> ... Set incoming UDP port number.\n",
         argv0);
}


int main(int argc, char **argv)
{
   struct sockaddr_in in;
   dns_trx_t *trx;
   int udp_sock, tcp_sock, udp_port = 53, family = AF_INET6;
   int c, bground = 0, debuglevel = LOG_INFO;

#ifdef TEST_UTDNS_FUNC
   test_utdns_func();
#endif

#ifdef DEBUG
   (void) init_log("stderr", debuglevel);
#endif

   while ((c = getopt(argc, argv, "4bdhp:")) != -1)
   {
      switch (c)
      {
         case '4':
            family = AF_INET;
            break;

         case 'b':
            bground++;
            break;

         case 'd':
            debuglevel = LOG_DEBUG;
            break;

         case 'h':
            usage(argv[0]);
            exit(EXIT_SUCCESS);

         case 'p':
            udp_port = atoi(optarg);
            break;
      }
   }

   if (argv[optind] == NULL)
   {
      usage(argv[0]);
      exit(EXIT_FAILURE);
   }

   // FIXME: this should not be hardcoded
   memset(&in, 0, sizeof(in));
   in.sin_family = AF_INET;
   in.sin_port = htons(53);
   if (!inet_aton(argv[optind], &in.sin_addr))
   {
      log_msg(LOG_ERR, "could not convert %s to in_addr\n", argv[optind]);
      exit(EXIT_FAILURE);
   }

   if ((udp_sock = init_udp_socket(family, udp_port)) == -1)
      perror("init_udp_socket"), exit(EXIT_FAILURE);

   if ((tcp_sock = init_tcp_socket(family, udp_port)) == -1)
      perror("init_tcp_socket"), exit(EXIT_FAILURE);

   drop_privileges();

   if (bground)
   {
      (void) init_log(NULL, debuglevel);
      background();
   }
   else
      (void) init_log("stderr", debuglevel);

   if ((trx = calloc(MAX_TRX, sizeof(*trx))) == NULL)
   {
      perror("calloc");
      (void) close(udp_sock);
      return -1;
   }

   dispatch_packets(udp_sock, tcp_sock, trx, MAX_TRX, (struct sockaddr*) &in, sizeof(in));
   free(trx);
   close(tcp_sock);
   close(udp_sock);

   return 0;
}

