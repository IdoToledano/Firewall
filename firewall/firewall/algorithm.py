# -*- coding: utf-8 -*-
from ip import IP
from port import Port
from scapy.all import *

IP_DICT = dict()
PORT_DICT = dict()
SUSPICIOUS_IPS = []
SUSPICIOUS_PORTS = []
SUSPICIOUS_VELOCITY = 150
SUSPICIOUS_ACCELERATION = 50
TIME_TO_SNIFF = 3


def sniff_ip(time_to_sniff):
    """
    Sniff packets which has IP during (time_to_sniff) seconds, summarizing them in a dictionary
    and returns that dictionary
    """
    ip_dict = dict()
    port_dict = dict()
    packets = sniff(timeout=time_to_sniff, filter="ip")

    for i in packets:
        sport = 0
        src = i['IP'].src

        if "TCP" in i:
            sport = i['TCP'].sport

        elif "UDP" in i:
            sport = i['UDP'].sport

        if not src in ip_dict.keys():
            ip_dict[src] = 1

        else:
            ip_dict[src] += 1

        if sport:
            if not sport in port_dict.keys():
                port_dict[sport] = 1

            else:
                port_dict[sport] += 1

    return ip_dict, port_dict


def get_suspicious():
    recent_ip, recent_port = sniff_ip(TIME_TO_SNIFF)
    for ip_src in recent_ip:
        if not ip_src in IP_DICT.keys():
            new_ip = IP(ip_src, TIME_TO_SNIFF)
            IP_DICT[ip_src] = new_ip

        IP_DICT[ip_src].add_count(recent_ip[ip_src])

    for port_src in recent_port:
        if not port_src in PORT_DICT.keys():
            new_port = Port(port_src, TIME_TO_SNIFF)
            PORT_DICT[port_src] = new_port

        PORT_DICT[port_src].add_count(recent_port[port_src])

    for ip_src in IP_DICT:
        data = IP_DICT[ip_src].get_data()
        if data['velocity'] > SUSPICIOUS_VELOCITY or data['acceleration'] > SUSPICIOUS_ACCELERATION:
            SUSPICIOUS_IPS.append(ip_src)

    for port_src in PORT_DICT:
        data = PORT_DICT[port_src].get_data()
        if data['velocity'] > SUSPICIOUS_VELOCITY or data['acceleration'] > SUSPICIOUS_ACCELERATION:
            SUSPICIOUS_PORTS.append(port_src)
    
    return SUSPICIOUS_IPS, SUSPICIOUS_PORTS
