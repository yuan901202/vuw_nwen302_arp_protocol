/*
 * NWEN 302 - Lab 2
 * Student Name: Tianfu Yuan
 * Student ID: 300228072
 * Username: yuantian
 */

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

/* My Code Begin */
/*
 * Etherent Packet
 */
typedef struct
{
    CnetNICaddr dest;    //hardware destination address
    CnetNICaddr sour;    //hardware source address
    char type[2];        //ethernet type
    char payload[1000];  //payload
} ETHER_PACKET;
/* My Code End */

int ethernet_send(CnetNICaddr to, unsigned short type, char *payload, size_t length);
void ethernet_init();

#endif	/* _ETHERNET_H_ */

