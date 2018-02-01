# -*- coding: utf-8 -*-
from ip import IP
from port import Port
from sniffer import sniff_ip


def get_suspicous_ips(time_to_sniff):
    IP_DICT = dict()
    PORT_DICT = dict()
    SUSPICOUS_IPS = []
    SUSPICOUS_VELOCITY = 150
    SUSPICOUS_ACCELERATION = 50

    recent_ip, recent_port = sniff_ip(time_to_sniff)
    for ip_src in recent_ip:
        if not ip_src in IP_DICT.keys():
            new_ip = IP(ip_src, time_to_sniff)
            IP_DICT[ip_src] = new_ip

        IP_DICT[ip_src].add_count(recent_ip[ip_src])
	
    for port_src in recent_port:
	if not port_src in PORT_DICT.keys():
            new_port = Port(port_src, time_to_sniff)
            PORT_DICT[port_src] = new_ip

        PORT_DICT[port_src].add_count(recent_port[port_src])

    for ip_src in IP_DICT:
        data = IP_DICT[ip_src].get_data()
        if data['velocity'] > SUSPICOUS_VELOCITY or abs(data['acceleration']) > SUSPICOUS_ACCELERATION:
	    SUSPICOUS_IPS.append(ip_src)
    
    return SUSPICOUS_IPS
	
