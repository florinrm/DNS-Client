#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>

#include "dns_message.h"
/*
+---------------------+
|       Header        |  
+---------------------+
|      Question       |		the question for the name server
+---------------------+
|       Answer        |		RRs answering the question
+---------------------+
|      Authority      |		RRs pointing toward an authority
+---------------------+
|     Additional      |		RRs holding additional information
+---------------------+
    
A (Host Address),
MX (Mail Exchange),
NS (Authoritative Name Server),
CNAME (the canonical name for an alias),
SOA (Start Of a zone of Authority),
TXT (Text strings) 
PTR (Domain Name Pointer) 
*/

struct timeval timeout;
const int val = 49152; // 1100 0000 0000 0000
const int size = 256; // max char size
const int max_size = 1024;

short int getType(char *record) {
	if (strcmp(record, "A") == 0)
		return htons(A);
	if (strcmp(record, "NS") == 0)
		return htons(NS);
	if (strcmp(record, "CNAME") == 0)
		return htons(CNAME);
	if (strcmp(record, "MX") == 0)
		return htons(MX);
	if (strcmp(record, "SOA") == 0)
		return htons(SOA);
	if (strcmp(record, "TXT") == 0)
		return htons(TXT);
	if (strcmp(record, "PTR") == 0)
		return htons(PTR);
	return -1;
}


void getTypeByString(unsigned short type, char* result) {
	if (type == A)
		strcpy(result, "A"); 
	else if (type == CNAME)
		strcpy(result, "CNAME");
	else if (type == MX)
		strcpy(result, "MX"); 
	else if (type == NS)
		strcpy(result, "NS");
	else if (type == PTR)
		strcpy(result, "PTR");
	else if (type == SOA)
		strcpy(result, "SOA");
	else if (type == TXT)
		strcpy(result, "TXT");
	else
		strcpy(result,  ""); 
}

void decompress (char *msg, char *label, int msg_length, int *length) {
	int i = msg_length, new_line = *length;

	while(msg[i] != '\0') {
		u_int ptr;
		memcpy(&ptr, msg + i, 2);
		ptr = ntohs(ptr);
		if (val <= ptr) {
			int offset = ptr - val;
			*length = new_line;
			decompress(msg, label, offset, &new_line);
			*length += 2;
			return;
		} else { 
			int mark = msg[i++];
			for (int j = 0; j < mark; ++j) {
				label[new_line++] = msg[i++];
			}
			label[new_line++] = '.';
		}
	}

	*length = new_line + 1;
	label[new_line] = 0;
}

void DNSResponseParsing (char* msg_received, int *answer_length, int dlog) {
	dns_rr_t rr;
	char aux[max_size], name[max_size], type[max_size], answer[max_size];
	int length = 0;
	
	decompress(msg_received, name, *answer_length, &length);
	*answer_length += length;
	memcpy(&rr, msg_received + (*answer_length), sizeof(dns_rr_t));
	memset(type, 0, sizeof(type));
	(*answer_length) += sizeof(dns_rr_t);
	rr.rdlength = ntohs(rr.rdlength);
	rr.type = ntohs(rr.type);

	int l = *answer_length;
	 *answer_length += rr.rdlength;

	getTypeByString(rr.type, type);
	sprintf(aux,"%s\tIN\t%s\t", name, type);
	write(dlog, aux, strlen(aux));
	
	
	switch(rr.type) {
		case PTR:
		case CNAME:
		case NS: {
			sprintf(aux, "%s\n", name + 2);
			decompress (msg_received, name, l, &length);
			write(dlog, aux, strlen(aux));
			break;
		}
		case MX: { 
			int preference;
			length = 0;
			memcpy (&preference, msg_received + l, 2);
			l += 2;
			sprintf(aux, "%d\t%s\n", ntohs (preference), answer);
			decompress (msg_received, answer, l, &length);
			write(dlog, aux, strlen(aux));
			break;

		}
		case TXT: { 
			char *data = (char *) malloc(sizeof (char) * rr.rdlength);
			memcpy (data, msg_received + l + 1, rr.rdlength);
			strcpy(aux, "\n");
			write(dlog, data, strlen(data) - 3);
			write(dlog, aux, strlen(aux));
			break;
		}
		case SOA: {
			u_int serial = 0, refresh = 0, retry = 0, expiration = 0, minimum = 0;
			char priName[size - 1], authoMailbox[size - 1];
			length = 0;

			memset(priName, 0, sizeof(priName));
			memset(authoMailbox, 0, sizeof(authoMailbox));
			decompress(msg_received, priName, l, &length);
			l += length;
			length = 0;
			printf("");
			decompress(msg_received, authoMailbox, l, &length);
			l += length;
			memcpy (&serial, msg_received + l, 4);
			l += 4;
			serial = ntohl (serial);
			
			memcpy (&refresh, msg_received + l, 4);
			l += 4;			
			refresh = ntohl (refresh);
			memcpy (&retry, msg_received + l, 4);
			l += 4;			
			retry = ntohl (retry);
			memcpy (&expiration, msg_received + l, 4);
			l += 4;			
			expiration = ntohl (expiration);
			memcpy (&minimum, msg_received + l, 4);
			l += 4;			
			minimum = ntohl (minimum);
			
			sprintf(aux, "%s\t%s\t%d\t%d\t%d\t%d\t%d\n", priName, authoMailbox, serial, refresh, retry, expiration, minimum);
			write(dlog, aux, strlen(aux));
			break;
		}
		case A:
			sprintf(aux, "%hhu.%hhu.%hhu.%hhu\n", msg_received[l], msg_received[l + 1], 
							msg_received[l + 2], msg_received[l + 3]);
			printf("Doing for A..."); // debugging							
			write(dlog, aux, strlen(aux));
			break;
		default :
			fprintf(stderr, "Unknown type!\n");
			break;
	}
}
//------------------------------------------------------------------------------

int main(int argc, char * argv[]) {

	if(argc < 3) {
		fprintf(stderr, "Wrong command format\n");
		exit(0);
	}
	
	char domain_name[size], record[size];
	strcpy(domain_name, argv[1]);
	strcpy(record, argv[2]);
	
	int mlog = open("message.log", O_WRONLY);
	if(mlog < 0)
		mlog = open("message.log", O_CREAT | O_WRONLY | O_TRUNC, 0644);
	else 
		mlog = open("message.log", O_WRONLY | O_APPEND);
	int dlog = open("dns.log", O_CREAT | O_WRONLY | O_APPEND, 0644);
	
	char *dns_servers[50];
	int servers = 0;
	char line [128]; 
	FILE *file = fopen ("dns_servers.conf", "r");
	if(file == NULL) {
		fprintf(stderr, "File doesn't exist! Exiting...\n");
		exit(0);
	}
	while (fgets (line, sizeof(line), file) != NULL) {
		if (line[0] == '#' || strcmp(line,"\n") == 0) 
			continue;
		dns_servers[servers] = (char*) malloc (strlen(line) + 1);
		line[strlen(line) - 1] = '\0';
		strcpy(dns_servers[servers], line);
		++servers;
	}
	fclose (file);
	
	
	char send_message[2 * size], recv_message[4 * size], aux[12 * size];
	char buffer[size], host[size];
	dns_header_t header;
	dns_question_t question;
	dns_rr_t rr;
	int i, length;
	struct in_addr ptr;
	u_int ptr_convers;

	memset (&header, 0, sizeof(header));

	header.qdcount = htons(1);
	header.rcode = header.aa = header.tc = 0;
	header.rd = 1;	
	header.id = htons(0);
	header.opcode = header.qr = header.z = header.ra = 0;

	header.ancount = header.nscount = header.arcount = 0;
	
	memset(buffer, 0, size);
	memset(send_message, 0, sizeof(send_message));
	memcpy(send_message, &header, sizeof(dns_header_t));
	int len_send = sizeof(dns_header_t);
	

	if (strcmp ("PTR", record) == 0) {
		inet_aton(domain_name, &ptr);
		ptr_convers = ntohl(*(u_int*)&ptr);
		ptr = *(struct in_addr*)&ptr_convers;
		printf("\n");
		sprintf(host,"%s.in-addr.arpa", inet_ntoa(ptr));
		strcpy(buffer + 1, host);
		
	} else
		strcpy(buffer + 1, domain_name);

	char count = 0;

	// QNAME
	printf("Trying \"%s\"\n", domain_name);	
	buffer[0] = '.';
	length = strlen(buffer);
	for (int i = length - 1; i > -1; --i)
		if (buffer[i] == '.') {
			sprintf(buffer + i, "%c%s", count, buffer + i + 1);
			count = 0;
		} else {
			count++;
		}
	buffer[strlen(buffer)] = '\0';
	
	memcpy(send_message + len_send, buffer, length + 1); // QNAME
	len_send += length;
	++len_send;
	
	question.qclass = htons(1);          // QCLASS - IN
	question.qtype = getType(record);	 // QTYPE
	memcpy(send_message + len_send, &question, sizeof(dns_question_t));
	len_send += sizeof(dns_question_t);

	
	int k = 0;
	for (int i = 0; i < sizeof(send_message); i++) {
		sprintf(aux + k, "%02X ", send_message[i]);
		k += 3;
	}

	write(mlog, aux, strlen(aux));
	fd_set read_fds;

	for(i = 0; i < servers; i++) {
		
		struct sockaddr_in serv_addr;
		FD_ZERO(&read_fds);
	
		int sockfd = socket(PF_INET, SOCK_DGRAM, 0);
		serv_addr.sin_port = htons(53);
		serv_addr.sin_family = AF_INET;
		inet_aton(dns_servers[i], &(serv_addr.sin_addr));
	
		if (connect(sockfd,(struct sockaddr*) &serv_addr, sizeof(serv_addr)) < 0)
			fprintf(stderr, "Error occurred during connection\n");
	
		int t_len = sizeof(serv_addr);
		int req = sendto(sockfd, send_message, len_send, 0, (struct sockaddr*) &serv_addr, t_len);
		if(req < 1) {
			fprintf(stderr, "Error occurred during sending\n");
			continue;
		}
		
		FD_SET(sockfd, &read_fds);
		
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		printf("Interrogation sent to %s\n",dns_servers[i]);
		int selection = select(sockfd + 1, &read_fds, NULL, NULL, &timeout);

		if(selection < 1) {
			if (selection != -1) {
				fprintf(stderr, "Server %s got timed out!\n\n", dns_servers[i]);
				close(sockfd);
				FD_CLR(sockfd, &read_fds);
				continue;
			} else {	
				fprintf(stderr, "Error: select didn't work properly\n");
			}
		}

		int received = recvfrom(sockfd, &recv_message, sizeof(recv_message), 
								0, (struct sockaddr*) &serv_addr, (socklen_t*) &t_len);
		
		if (0 > received) {
			fprintf(stderr, "Error occurred during message receiving\n");
			continue;
		}
		
		memcpy(&header, recv_message, sizeof(dns_header_t));
		if (header.rcode != 0) {
			fprintf(stderr,"Server %s did not response!\n", dns_servers[i]);
			continue;
		}
		
		int arcount = ntohs (header.arcount), nscount = ntohs (header.nscount);
		int ancount = ntohs (header.ancount);

		
		sprintf(aux, "; %s - %s %s\n\n", dns_servers[i], domain_name, record);
		printf("ANSWER SECTION:%d AUTHORITY SECTION:%d ADDITIONAL SECTION:%d\n\n", ancount, nscount, arcount);
		write(dlog, aux, strlen(aux));

		
		int offset = sizeof (dns_header_t), qname_len = 0;
		memset(buffer, 0, sizeof(buffer));
		decompress (recv_message, buffer, offset, &qname_len);
		offset += qname_len + sizeof (dns_question_t);
		
		// ANSWER SECTION
		if (ancount > 0){
			write(dlog, aux, strlen(aux));
			sprintf(aux, ";; %s:\n", "ANSWER SECTION");
			while(ancount > 0) {
				--ancount;
				DNSResponseParsing(recv_message, &offset, dlog);
			}
			strcpy(aux,"\n");
			write(dlog, aux, strlen(aux));
		} 
		// AUTHORITY SECTION 
		if (nscount > 0){
			write(dlog, aux, strlen(aux));			
			sprintf(aux, ";; %s:\n", "AUTHORITY SECTION");
			while(nscount > 0) {
				--nscount;
				DNSResponseParsing(recv_message, &offset, dlog);
			}
			strcpy(aux,"\n");
			write(dlog, aux, strlen(aux));
		 
		}
		// ADDITIONAL SECTION 
		
		if (arcount > 0){
			write(dlog, aux, strlen(aux));
			sprintf(aux, ";; %s:\n", "ADDITIONAL SECTION");
			while(arcount > 0) {
				--arcount;
				DNSResponseParsing(recv_message, &offset, dlog);
			}
		 
		} 
		strcpy(aux,"\n\n");
		printf("Answer processed!\n");
		write(dlog, aux, strlen(aux));
		
		FD_CLR(sockfd, &read_fds);
		close(sockfd);
		break;
	}
	
	close(mlog);
	close(dlog);	
	return 0;
}
