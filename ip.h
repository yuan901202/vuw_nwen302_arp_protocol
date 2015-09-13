/*
 * NWEN 302 - Lab 2
 * Student Name: Tianfu Yuan
 * Student ID: 300228072
 * Username: yuantian
 */

/*
 * ip.h
 *
 * David C. Harrison (davidh@ecs.vuw.ac.nz) September 2014
 *
 */

#ifndef _IP_H_
#define	_IP_H_

#include <cnet.h>

#define IPPROTO_STOP_AND_WAIT	254

/* My Code Begin */
/*
 * Prototypes
 */
typedef uint32_t IPAddr;
IPAddr network_local_address(void);
bool network_is_valid(IPAddr ip);
int network_unpause_destination(IPAddr dest_ip);
const char *network_display_address(IPAddr ip);
/* My Code End */

void ip_accept(char *packet, size_t length);
void ip_send(CnetAddr to, unsigned char protocol, char *payload, size_t length);
void ip_init();

#endif	/* _IP_H_ */

