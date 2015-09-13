/*
 * NWEN 302 - Lab 2
 * Student Name: Tianfu Yuan
 * Student ID: 300228072
 * Username: yuantian
 */

/*
 * arp.c
 *
 * David C. Harrison (davidh@ecs.vuw.ac.nz) September 2014
 *
 * Beyond simplistic ARP implementation.
 *
 */

/* My Code Begin */
#include <assert.h>
#include <stdbool.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include "cnet.h"
/* My Code End */

#include "arp.h"
#include "ip.h"
#include "ethernet.h"

/* My Code Begin */
#define IP_ADDRLEN 4
#define LEN_NICADDR 6
#define MAX_ADDR 255
#define LAN_LINK 1
#define IP_CODE 0x0800
#define ETH_CODE 0x0001
#define ARP_CODE 0x0806
#define ARP_REQUEST_CODE 1 
#define ARP_REPLY_CODE 2

/*
 * ARP packet
 */
typedef struct
{
    uint16_t htype;        //hardware type
    uint16_t ptype;        //protocol type
    uint8_t hlen;          //hardware length
    uint8_t plen;          //protocol length
    uint16_t opcode;       //operation code - 1 for request, 2 for reply
    CnetNICaddr sour_mac;  //source hardware address
    IPAddr sour_ip;        //source protocol address
    CnetNICaddr dest_mac;  //destination hardware address
    IPAddr dest_ip;        //destination protocol address
} ARP_PACKET;

/*
 * ARP Table
 */
struct arp_table_init
{
    IPAddr ipAddress[MAX_ADDR];         //protocol address
    CnetNICaddr macAddress[MAX_ADDR];   //hardware address
    int ttl;                            //TTL - time to live
} arp_table;

struct arp_table_init table[20];  //arp table size
int arp_table_index;  //arp table index

/*
 * Prototypes
 */
void receive_arp_packet(char *string, ARP_PACKET *arp_packet);
int handle_arp_packet(ARP_PACKET *arp_packet);
int query_arp_table(const IPAddr ip);
void update_arp_table(CnetNICaddr mac, int pos);
void add_arp_table(IPAddr ip, CnetNICaddr mac);
void arp_request(ARP_PACKET *arp_packet);
void print_arp_table();
/* My Code End */

bool arp_get_mac_address(CnetAddr cnetAddress, CnetNICaddr macAddress)
{
    switch (cnetAddress) {
        case 0:
            CNET_parse_nicaddr(macAddress, "00:90:27:41:B0:BE");
            break;
        case 1:
            CNET_parse_nicaddr(macAddress, "01:90:27:62:58:84");
            break;
        case 2:
            CNET_parse_nicaddr(macAddress, "02:20:58:12:07:37");
            break;
        case 3:
            CNET_parse_nicaddr(macAddress, "03:8C:E6:3B:36:63");
            break;
        case 4:
            CNET_parse_nicaddr(macAddress, "04:F7:4E:C5:7F:32");
            break;
        case 5:
            CNET_parse_nicaddr(macAddress, "05:A0:C9:AF:9E:81");
            break;
        case 6:
            CNET_parse_nicaddr(macAddress, "06:EB:26:50:38:7D");
            break;
        case 7:
            CNET_parse_nicaddr(macAddress, "07:88:B6:09:09:AB");
            break;
        case 8:
            CNET_parse_nicaddr(macAddress, "08:3B:AF:D2:AA:53");
            break;
        default:
            return false;
    }
    return true;
}

/* My Code Begin */
/*
 * The following code is based on ETSIT/UVa' ethernetconarp.c.
 * Link: http://desa.tel.uva.es/descargar.htm?id=771
 */

/*
 * Transfer ARP packet that received from the physical layer
 */
void receive_arp_packet(char *string, ARP_PACKET *arp_packet)
{
    char *str = string;  //string pointer
    assert(string != NULL && arp_packet != NULL);
    
    //hardware type
    memcpy(&arp_packet->htype, str, sizeof(uint16_t));
    arp_packet->htype = ntohs(arp_packet->htype);
    str += sizeof(uint16_t);
    
    //protocol type
    memcpy(&arp_packet->ptype, str, sizeof(uint16_t));
    arp_packet->ptype = ntohs(arp_packet->ptype);
    str += sizeof(uint16_t);
    
    //hardware length
    memcpy(&arp_packet->hlen, str, sizeof(uint8_t));
    str += sizeof(uint8_t);
    
    //protocol length
    memcpy(&arp_packet->plen, str, sizeof(uint8_t));
    str += sizeof(uint8_t);
    
    //operation code - 1 for request, 2 for reply
    memcpy(&arp_packet->opcode, str, sizeof(uint16_t));
    arp_packet->opcode = ntohs(arp_packet->opcode);
    str += sizeof(uint16_t);
    
    //source hardware address
    memcpy(arp_packet->sour_mac, str, sizeof(CnetNICaddr));
    str += sizeof(CnetNICaddr);

    //source protocol address
    memcpy(&arp_packet->sour_ip, str, sizeof(IPAddr));
    printf("Source IP: %s \n", network_display_address(arp_packet->sour_ip));
    str += sizeof(IPAddr);

    //destination hardware address
    if (arp_packet->opcode == ARP_REPLY_CODE){
	memcpy(arp_packet->dest_mac, str, sizeof(CnetNICaddr));
    }
    
    //destination protocol address
    str += sizeof(CnetNICaddr);
    memcpy(&arp_packet->dest_ip, str, sizeof(IPAddr));
    printf("Destination IP: %s \n", network_display_address(arp_packet->dest_ip));
}

/*
 * Handle arp packet
 */
int handle_arp_packet(ARP_PACKET *arp_packet)
{
    bool addtoarptable = false;
    char sourmac[18];  //source hardware address
    const char *sourip = network_display_address(arp_packet->sour_ip);
    
    CNET_format_nicaddr(sourmac, arp_packet->sour_mac);
    printf("ARP packet source MAC: %s \n", sourmac);
    
    //handle arp ethernet
    if (arp_packet->htype  == ETH_CODE){
	if (arp_packet->hlen == LEN_NICADDR){
	    if (arp_packet->ptype == IP_CODE){
		if (arp_packet->plen == IP_ADDRLEN){
		    int pos = 0;
		    pos = query_arp_table(arp_packet->sour_ip);
		    
		    if (pos != -1){
			printf("Update ARP table - source IP: %s \n", sourip);
			update_arp_table(arp_packet->sour_mac, pos);
			addtoarptable = true;
		    } else {
			printf("Add source IP to ARP table: %s \n", sourip);
			IPAddr sour_ip = arp_packet->sour_ip;
			add_arp_table(sour_ip, arp_packet->sour_mac);
			CHECK(network_unpause_destination(sour_ip));
		    }
		    
		    if (arp_packet->dest_ip == network_local_address()){
			if (!addtoarptable){
			    printf("Add source IP to ARP table: %s \n", sourip);
			    IPAddr sour_ip = arp_packet->sour_ip;
			    add_arp_table(sour_ip, arp_packet->sour_mac);
			}
			
			if (arp_packet->opcode == ARP_REQUEST_CODE){
			    CnetNICaddr nicAddress;
			    IPAddr ip1 = 0, ip2 = 0;
			    
			    printf("ARP response IP: %s \n", sourip);
			    arp_packet->opcode = ARP_REPLY_CODE;
			    
			    memcpy(nicAddress, arp_packet->sour_mac, sizeof(CnetNICaddr));
			    memcpy(arp_packet->sour_mac, linkinfo[1].nicaddr, sizeof(CnetNICaddr));
			    memcpy(arp_packet->dest_mac, nicAddress, sizeof(CnetNICaddr));
			    
			    ip1 = arp_packet->sour_ip;
			    ip2 = network_local_address();
			    
			    arp_packet->sour_ip = ip2;
			    arp_packet->dest_ip = ip1;
			    
			    arp_request(arp_packet);
			}
		    }
		} else {
		    printf("IP address length error! (should be equal to 4) \n");
		    return -1;
		}
	    } else {
		printf("Ethernet protocol error! (should be IPv4) \n");
		return -1;
	    }
	} else {
	    printf("MAC address length error! (should be equal to 6) \n");
	    return -1;
	}
    } else {
	printf("Hardware protocol error! (should be Ethernet) \n");
	return -1;
    }
    
    return 0;
}

/*
 * Query arp table 
 */
int query_arp_table(const IPAddr ip)
{
    int i = 0;
    int pos = -1; //postion
    IPAddr currentIP = 0;
    
    assert(network_is_valid(ip));
    
    for (i = 0; i < arp_table.ttl; i++){
	currentIP = arp_table.ipAddress[i];
	
	if (currentIP == ip){
	    pos = i;
	    break;
	}
    }
    
    return pos;
}

/*
 * Update arp table
 */
void update_arp_table(CnetNICaddr mac, int pos)
{
   assert(0 <= pos && pos < arp_table.ttl);
   memcpy(arp_table.macAddress[pos], mac, sizeof(CnetNICaddr));
}

/*
 * Add arp table
 */
void add_arp_table(IPAddr ip, CnetNICaddr mac)
{
    assert(network_is_valid(ip));
    arp_table.ipAddress[arp_table.ttl] = ip;
    memcpy(mac, arp_table.macAddress[arp_table.ttl], sizeof(CnetNICaddr));
    arp_table.ttl += 1;
}

/*
 * Reply arp request
 */
void arp_request(ARP_PACKET *arp_packet)
{
    assert(arp_packet != NULL);
    int link = LAN_LINK;
    ETHER_PACKET packet;
    
    uint16_t code = 0;
    size_t len = 0;
    
    code = htons(ARP_CODE);
    
    memcpy(packet.dest, arp_packet->dest_mac, sizeof(CnetNICaddr));
    memcpy(packet.sour, arp_packet->sour_mac, sizeof(CnetNICaddr));
    memcpy(packet.type, &code, sizeof(packet.type));
    memcpy(packet.payload, arp_packet, sizeof(ARP_PACKET));
    
    len = sizeof(packet);
    CHECK(CNET_write_physical(link, &packet, &len));
}

/*
 * Print out arp table
 */
void print_arp_table()
{
    int i;
    char strbuf[24];
    
    printf("\n ARP TABLE: \n");
    for (i = 0; i < arp_table_index; i++){
	//CNET_format_nicaddr(strbuf, table[i].macAddress);  //ERROR???
	printf("Entry %i: %i => %s \n", i, table[i].ipAddress , strbuf);
    }
    printf("\n === END === \n");
}
/* My Code End */

