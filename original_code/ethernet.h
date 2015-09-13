/*
 * ethernet.h
 *
 * David C. Harrison (davidh@ecs.vuw.ac.nz) September 2014
 *
 */

#ifndef _ETHERNET_H_
#define	_ETHERNET_H_

#include <cnet.h>

#define	ETHERTYPE_IP	0x0800		/* Internet Protocol Version 4 */
#define	ETHERTYPE_ARP	0x0806		/* Address Resolution Protocol */

int ethernet_send(CnetNICaddr to, unsigned short type, char *payload, size_t length);
void ethernet_init();

#endif	/* _ETHERNET_H_ */

