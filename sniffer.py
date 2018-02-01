# -*- coding: utf-8 -*-
from scapy.all import *


def sniff_ip(time_to_sniff):
    """
    Sniff packets which has IP during (time_to_sniff) seconds, summarizing them in a dictionary
    and returns that dictionary
    """
    ip_dict = dict()
    port_dict = dict()
    packets = sniff(timeout=time_to_sniff, filter="udp || tcp")

    for i in xrange(len(packets)):
        src = packets[i]['IP'].src
	if TCP in packets[i]:
	    sport = packets[i]['TCP'].sport
	else:
	    sport = packets[i]['UDP'].sport

        if not src in ip_dict.keys():
            ip_dict[src] = 1

        else:
            ip_dict[src] += 1


	if not sport in port_dict.keys():
	    port_dict[sport] = 1

	else:
	    port_dict[sport] += 1

    return  ip_dict, port_dict
