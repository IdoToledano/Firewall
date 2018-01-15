# -*- coding: utf-8 -*-
from ip import IP
from sniffer import sniff_ip

IP_DICT = dict()


def main():
    time_to_sniff = int(raw_input("Enter frequency of sniffing (in seconds): "))

    while True:
        recent_requests = sniff_ip(time_to_sniff)
        for ip_src in recent_requests:
            if not ip_src in IP_DICT.keys():
                new_ip = IP(ip_src, time_to_sniff)
                IP_DICT[ip_src] = new_ip

            IP_DICT[ip_src].add_count(recent_requests[ip_src])

        for ip_src in IP_DICT:
            data = IP_DICT[ip_src].get_data()
            for key in data:
                print "{0}: {1}".format(key, data[key])


if __name__ == '__main__':
    main()