/*
 * NWEN 302 - Lab 2
 * Student Name: Tianfu Yuan
 * Student ID: 300228072
 * Username: yuantian
 */

/*
 * ip.c
 *
 * David C. Harrison (davidh@ecs.vuw.ac.nz) September 2014
 *
 * Simplistic IPv4 network layer for cnet v3.2.4, tightly coupled to the
 * associated Ethernet data-link and StopAndWait transport layers.
 *
 */

/* My Code Begin */
#include <assert.h>
#include "ip.h"
/* My Code End */

#include <stdlib.h>
#include <string.h>
#include "arp.h"
#include "ethernet.h"
#include "stopandwait.h"

// Assumes little endian (Intel processor)
typedef struct {
    unsigned int   header_length;
    unsigned int   version;
    unsigned short type_of_service;
    unsigned short total_length;
    unsigned short id;
    unsigned short fragment_offset;
    unsigned char  time_to_live;
    unsigned char  protocol;
    unsigned short checksum;
    CnetAddr       source;
    CnetAddr       destination;
} IpHeader;

#define IP_HEADER_SIZE sizeof(IpHeader)

/* My Code Begin */
#define DEFAULT_NETWORK ((IPAddr)0x0000a8c0)  //192.168.0.X
#define NETMASK ((IPAddr)0x00FFFFFF)  //255.255.255.0/24
#define MAX_ADDRESS 255  //max ip address number
#define IP_SIZE 30  //ip size
/* My Code End */

void ip_accept(char *packet, size_t length)
{
    IpHeader *header = (IpHeader *)packet;
    stopandwait_accept(
        packet + header->header_length,
        length - header->header_length);
}

void ip_send(CnetAddr to, unsigned char protocol, char *payload, size_t length)
{
    IpHeader header;
    header.header_length = IP_HEADER_SIZE;
    header.protocol = protocol;
    header.total_length = (unsigned short) (IP_HEADER_SIZE + length);
    header.source = nodeinfo.address;
    header.destination = to;

    char *packet = calloc(1, header.total_length);
    memcpy(packet, (char *) &header, IP_HEADER_SIZE);
    memcpy(packet + IP_HEADER_SIZE, payload, (int) length);

    CnetNICaddr destAddr;
    if (arp_get_mac_address(to, destAddr)) {
        ethernet_send(destAddr, ETHERTYPE_IP, packet, header.total_length);
    }
    free(packet);
}

void ip_init()
{
    ethernet_init();
}

/* My Code Begin */
IPAddr network_local_address(void)
{
    assert(nodeinfo.address < MAX_ADDRESS);
    return ((IPAddr)DEFAULT_NETWORK + ((IPAddr)(nodeinfo.address)<<24));
}

bool network_is_valid(IPAddr ip)
{
    return ((ip & NETMASK) == DEFAULT_NETWORK);
}

int network_unpause_destination(IPAddr dest_ip) 
{
    assert (network_is_valid(dest_ip));
    return CNET_enable_application((dest_ip & NETMASK) >> 24);
}

const char *network_display_address(IPAddr ip)
{
    static char ipsize[IP_SIZE];
    snprintf(ipsize, IP_SIZE, "%d.%d.%d.%d", ip & 0xff, (ip >> 8) & 0xff, (ip >> 16) & 0xff, (ip >> 24) & 0xff);
    ipsize[IP_SIZE] = '\0';
    return ipsize;
}
/* My Code End */

