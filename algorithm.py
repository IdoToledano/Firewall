# -*- coding: utf-8 -*-
from ip import IP
from sniffer import sniff_ip

IP_DICT = dict()


def main():
    time_to_sniff = float(raw_input("Enter frequency of sniffing (in seconds): "))

    while True:
        recent_requests = sniff_ip(time_to_sniff)
        for ip_src in recent_requests:
            if not ip_src in IP_DICT.keys():
                new_ip = IP(ip_src, time_to_sniff)
                IP_DICT[ip_src] = new_ip

            IP_DICT[ip_src].add_count(recent_requests[ip_src])

        for ip_src in IP_DICT:
            data = IP_DICT[ip_src].get_data()
            if data['velocity'] > 10 or abs(data['acceleration']) > 5:
                print "---IP---\nip: {}\nvelocity: {}\nacceleration: {}".format(data['ip'], data['velocity'], data['acceleration'])


if __name__ == '__main__':
    main()