/*
 * arp.c
 *
 * David C. Harrison (davidh@ecs.vuw.ac.nz) September 2014
 *
 * Beyond simplistic ARP implementation.
 *
 */

#include "arp.h"

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
