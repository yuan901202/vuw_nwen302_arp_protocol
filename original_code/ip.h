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

void ip_accept(char *packet, size_t length);
void ip_send(CnetAddr to, unsigned char protocol, char *payload, size_t length);
void ip_init();

#endif	/* _IP_H_ */

