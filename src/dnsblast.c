/*
	hdm@digitaloffense.net
	$ sudo apt-get install libc-ares-dev
	$ gcc -o dnsblast dnsblast.c -lcares -lrt -lpthread -static && strip dnsblast
	$ echo 8.8.8.8 | ./dnsblast 
	  8.8.8.8	google-public-dns-a.google.com	0
*/



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
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <netdb.h>
#include <sys/time.h>
#include <pthread.h>
#include <ares.h>


ares_channel dns_channel;
struct ares_options dns_options;

// Globals
unsigned long long pkt_recv = 0;
unsigned long long pkt_sent = 0;
unsigned long long pkt_errs = 0;
unsigned long long pkt_fail = 0;
int s;

int shutting_down = 0;

// Callback for responses
void handle_replies(void *arg, int status, int timeouts, struct hostent *host) {
	struct sockaddr_in daddr4;
	unsigned char buf[INET6_ADDRSTRLEN+1];
	pkt_recv++;

	switch(status) {
	case ARES_ENOTIMP:
		fprintf(stderr, "Error: address family not implemented\n");
		break;
	case ARES_ENOMEM:
		fprintf(stderr, "Error: no memory\n");
		break;
	case ARES_EDESTRUCTION:
		fprintf(stderr, "Error: destruction\n");
		break;
	case ARES_ENOTFOUND:
		pkt_fail++;
		break;
	case ARES_SUCCESS:
		inet_ntop(AF_INET, host->h_addr, buf, INET6_ADDRSTRLEN);
		fprintf(stdout, "%s\t%s\t%d\n", buf, host->h_name, timeouts);
		fflush(stdout);
		break;
	default:
		break;
	}
}

void process_data_manually() {
    fd_set readers, writers;
    struct timeval tv, *tvp;
	int nfds, count;

	do {
		FD_ZERO(&readers);
		FD_ZERO(&writers);
		nfds = ares_fds(dns_channel, &readers, &writers);

		if (nfds == 0) break;

		tv.tv_sec = 0;
		tv.tv_usec = 10000;

		count = select(nfds, &readers, &writers, NULL, &tv);
		if (count == 0) break;

		ares_process(dns_channel, &readers, &writers);
	} while(1);
}

// Interrupt handler
void handle_interrupt(int signum) {
	if(shutting_down) exit(1);
	shutting_down = 1;
	fprintf(stderr, "Interrupt: shutting down threads...\n");
}


// Main
int main(int argc, char *argv[])
{
	int r, c, e, flags, rbuf;
	int port;
	
	FILE *fd;
	unsigned char *str;
	unsigned char *pkt_buf;
	unsigned char *daddr_copy;
	unsigned int pkt_len;
	unsigned char line[256];
	float elapsed;
	float rate;
	unsigned int dns_concurrent = 1000;
	
	pthread_t t_recv;

	struct timeval stime, tv;
	struct stat st;

	struct sockaddr *daddr;
	socklen_t daddr_len;
	
	struct sockaddr_in daddr4;
	socklen_t daddr4_len = sizeof(struct sockaddr_in);
	
	// Temporary argument to callback
	unsigned long arg;
	
	memset((char *) &daddr4, daddr4_len, 0);

	signal(SIGINT, handle_interrupt);
	
	// Mark our start time
	gettimeofday(&stime, NULL);
	pkt_sent = 0;

	// Initialize IPv4 sockaddr
	daddr4.sin_family = AF_INET;
    daddr4.sin_port = 53;

	// Set the shut down flag to zero
	shutting_down = 0;

	memset(&dns_options, 0, sizeof(dns_options));
	dns_options.tries    = 1;
	dns_options.timeout  = 4;


	if (argc < 4) {
		fprintf(stderr, "Usage: %s [tries] [timeout] [concurrency]\n", argv[0]);
		exit(1);
	}

	dns_options.tries = atoi(argv[1]);
	dns_options.timeout = atoi(argv[2]);
	dns_concurrent = atoi(argv[3]);

	// Create our ARES channel
	if (ARES_SUCCESS != ares_init_options(&dns_channel, &dns_options, ARES_OPT_FLAGS | ARES_OPT_TIMEOUT | ARES_OPT_TRIES | ARES_FLAG_IGNTC )) {
	//if (ARES_SUCCESS != ares_init(&dns_channel)) {
		fprintf(stderr, "Failed to initialize ARES\n");
		exit(0);
	}
 
    // Read hosts from stdin and spam requests
    while((str = fgets(line, sizeof(line)-1, stdin)) != NULL && ! shutting_down) {
    	str = strchr(line, 0x0a);
    	if (str) *str = 0;

		inet_pton(AF_INET, line, &(daddr4.sin_addr));
		ares_gethostbyaddr(dns_channel, &daddr4.sin_addr, sizeof(daddr4.sin_addr), AF_INET, handle_replies, NULL);
    	
		pkt_sent++;

		while (pkt_sent - pkt_recv > dns_concurrent) {
			process_data_manually();
		}
    }
  
	while (pkt_sent > pkt_recv) {
		process_data_manually();
		usleep(10000);
	}

	// Shutdown active threads
	shutting_down = 1;
	
	// Cancel any pending requests
	ares_cancel(dns_channel);

	// Destroy
    ares_destroy(dns_channel);

    return 0;
}
