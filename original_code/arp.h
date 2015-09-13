/*
 * arp.h
 *
 * David C. Harrison (davidh@ecs.vuw.ac.nz) September 2014
 *
 */

#ifndef _ARP_H_
#define	_ARP_H_

#include <cnet.h>

bool arp_get_mac_address(CnetAddr cnetAddress, CnetNICaddr macAddress);

#endif	/* _ARP_H_ */

