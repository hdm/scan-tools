#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/select.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <netdb.h>
#include <sys/time.h>
#include <pthread.h>

// Globals
unsigned long long pkt_recv = 0;
unsigned long long pkt_sent = 0;
unsigned long long pkt_errs = 0;
unsigned long long pkt_fail = 0;
unsigned short dport;
char *data_file;

int s;

int shutting_down = 0;


// Receive thread
void process_data(void * ignored) {

	int plen, wlen, ret, i;

	struct sockaddr_storage saddr;
	struct sockaddr_in *saddr4;
	struct sockaddr_in6 *saddr6;
	struct timeval stime;
	unsigned short sport;

	int saddr_len;
	unsigned char *data;
	unsigned char *line;
	unsigned char *ptr;
	unsigned char addr[128];

	struct timeval timeout;

	fd_set rfd, wfd, efd;

	data = malloc(9000);
	if (! data) {
		fprintf(stderr, "Failed to allocate receive buffer\n");
		shutting_down = 1;
		return;
	}

	line = malloc(9100);
	if (! line) {
		free(data);
		fprintf(stderr, "Failed to allocate output buffer\n");
		shutting_down = 1;
		return;
	}

	while (! shutting_down) {
		do {
			saddr_len = sizeof(struct sockaddr_storage);
			plen = recvfrom(s, data, 8999, 0, (struct sockaddr *)&saddr, &saddr_len);
			if (plen <= 0) break;

			memset(addr, 0, sizeof(addr));
			if (saddr.ss_family == AF_INET) {
				saddr4 = (struct sockaddr_in *)&saddr;
				inet_ntop(saddr.ss_family, &saddr4->sin_addr, addr, sizeof(addr)-1);
				sport = ntohs(saddr4->sin_port);
				ptr = addr;
			} else {
				saddr6 = (struct sockaddr_in6 *)&saddr;
				inet_ntop(saddr.ss_family, &saddr6->sin6_addr, addr, sizeof(addr)-1);
				sport = ntohs(saddr6->sin6_port);

				ptr = strstr(addr, "::ffff:");
				ptr = ptr ? (addr + 7) : addr;
			}

			gettimeofday(&stime, NULL);

			fprintf(stdout, "%u\t%s\t%d\t%d\t%s\t", (unsigned int)stime.tv_sec, ptr, sport, dport, data_file);
			for (i=0; i<plen; i++) {
				fprintf(stdout, "%.2x", data[i]);
			}
			fprintf(stdout, "\n");
			fflush(stdout);

			pkt_recv++;
		} while(plen > 0);

		usleep(100);
	}

	free(line);
	free(data);

	shutting_down = 1;
}


// Interrupt handler
void handle_interrupt(int signum) {
	shutting_down = 1;
}


// Main
int main(int argc, char *argv[])
{
	int r, c, e, flags, rbuf;
	int port;

	FILE *fd;
	unsigned char *str;
	unsigned char *pkt_buf;
	unsigned int pkt_len;
	unsigned char line[256];
	unsigned long pps = 1000;
	float elapsed;
	float rate;

	pthread_t t_recv;


	struct timeval stime, tv;
	struct stat st;

	struct sockaddr *daddr;
	socklen_t daddr_len;

	struct sockaddr_in daddr4;
	socklen_t daddr4_len = sizeof(struct sockaddr_in);

	struct sockaddr_in6 daddr6;
	socklen_t daddr6_len = sizeof(struct sockaddr_in6);

	memset((char *) &daddr4, daddr4_len, 0);
	memset((char *) &daddr6, daddr6_len, 0);


	struct sockaddr *baddr;
	socklen_t baddr_len;

	struct sockaddr_in baddr4;
	socklen_t baddr4_len = sizeof(struct sockaddr_in);

	struct sockaddr_in6 baddr6;
	socklen_t baddr6_len = sizeof(struct sockaddr_in6);

	memset((char *) &daddr4, daddr4_len, 0);
	memset((char *) &daddr6, daddr6_len, 0);


	// 128Mb receive buffer
	rbuf = (1024*1024*128);

    if (argc < 3 || argc > 6) {
        fprintf(stderr,"usage: <port> <packet-file> [pps-rate] [bind-address] [bind-port]\n");
        exit(1);
    }

    if (argc >= 4) pps = atoi(argv[3]);
    if (argc >= 5) {
     	// IPv6

     	if (strchr(line, 0x3a) != NULL) {
			inet_pton(AF_INET6, argv[4], &(baddr6.sin6_addr));
		} else {
			snprintf(line, sizeof(line)-1, "::ffff:%s", argv[4]);
			inet_pton(AF_INET6, line, &(baddr6.sin6_addr));
		}

    	baddr = (struct sockaddr *)&baddr6;
    	baddr_len = baddr6_len;

		// Initialize IPv6 sockaddr
		baddr6.sin6_family = AF_INET6;
   	 	baddr6.sin6_port = 0;
    	baddr6.sin6_flowinfo = 0;
   		baddr6.sin6_scope_id = 0;

   		if (argc >= 6)
	   		baddr6.sin6_port = htons(atoi(argv[5]));

    }


	signal(SIGINT, handle_interrupt);

	// Mark our start time
	gettimeofday(&stime, NULL);
	pkt_sent = 0;

	// Save the destination port
	dport = atoi(argv[1]);

	// Save the data file path
	data_file = argv[2];

	// Initialize IPv6 sockaddr
	daddr6.sin6_family = AF_INET6;
    daddr6.sin6_port = htons(dport);
    daddr6.sin6_flowinfo = 0;
    daddr6.sin6_scope_id = 0;

	// Initialize IPv4 sockaddr
	daddr4.sin_family = AF_INET;
    daddr4.sin_port = htons(dport);

    // Read our packet file
    fd = fopen(argv[2], "rb");
    if (! fd) {
    	fprintf(stderr, "Failed to open packet file");
    	return(1);
    }

    fstat(fileno(fd), &st);
    pkt_buf = malloc(st.st_size);
    if (! pkt_buf) {
    	fprintf(stderr, "Failed to allocate memory");
    	fclose(fd);
    	return(1);
    }

    pkt_len = st.st_size;

    r = fread(pkt_buf, 1, st.st_size, fd);
    if (r != st.st_size) {
    	fprintf(stderr, "Short read of packet file: %u vs %u", r, (unsigned int) st.st_size);
    	fclose(fd);
    	return(1);
    }
    fclose(fd);

	// Create our UDP socket
    s = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (! s) {
 		fprintf(stderr, "Failed to open UDP socket");
		return 1;
    }

    if (argc >= 5) {
  		if (bind(s, baddr, baddr_len) < 0) {
			fprintf(stderr, "Failed to bind UDP socket");
			return 1;
  		}
  	}

    // Mark it as non-blocking
    flags = fcntl(s, F_GETFL);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);

    // Increase the receive buffer size
    setsockopt(s, SOL_SOCKET, SO_RCVBUF, &rbuf, sizeof(rbuf));

    rbuf = (1024*1024*128);
    setsockopt(s, SOL_SOCKET, SO_SNDBUF, &rbuf, sizeof(rbuf));

	// Kick off the listener thread
 	pthread_create(&t_recv, NULL, (void *) &process_data, (void *) 0);

    // Read hosts from stdin and spam packets
    while((str = fgets(line, sizeof(line)-1, stdin)) != NULL && ! shutting_down) {
    	str = strchr(line, 0x0a);
    	if (str) *str = 0;

    	// IPv6
    	if (strchr(line, 0x3a) != NULL) {
			inet_pton(AF_INET6, line, &(daddr6.sin6_addr));
    		daddr = (struct sockaddr *)&daddr6;
    		daddr_len = daddr6_len;
    	// IPv4
    	} else {
			inet_pton(AF_INET, line, &(daddr4.sin_addr));
 	    	daddr = (struct sockaddr *)&daddr4;
    		daddr_len = daddr4_len;
    	}

    	// Set the retry counter to zero
    	c = 0;

    	do {
			r = sendto(s, pkt_buf, pkt_len, 0, (struct sockaddr *) daddr, daddr_len);

			// Triggered in rare cases
			if (r == -1 && errno == EACCES) {
				break;
			}

			if (r <= 0) {
				pkt_errs += 1;
				usleep(250);
				if ( (c++) > 12) pkt_fail +=1;
				continue;
			}

			pkt_sent++;

			if (pkt_sent % 100 == 0) {
				while(! shutting_down) {
					gettimeofday(&tv, NULL);
					elapsed = (tv.tv_sec - stime.tv_sec);
					if (elapsed == 0 && pkt_sent < pps) break;
					rate = (elapsed == 0) ? pkt_sent :  (pkt_sent / elapsed);
					if (rate > pps) {
						usleep(50);
						continue;
					}
					break;
				}
			}

		} while (r <= 0 && c < 13 && !shutting_down);
    }

    // Wait 5 seconds for replies to trickle in
    if (! shutting_down) {
    	sleep(5);
    }

	// Shutdown active threads
	shutting_down = 1;


	// Wait for the receive thread to finish
	pthread_join(t_recv, NULL);


    close(s);

    return 0;
}
