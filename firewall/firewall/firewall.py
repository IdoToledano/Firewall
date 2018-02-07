from ip_tables import IpTables
from algorithm import get_suspicious
import Tkinter as tk
import threading


TIME_TO_SNIFF = 100


def ban_by_ip(f, ip):
    ip = ip.get()
    f.block_ip(ip)


def ban_by_port(f, port):
    port = port.get()
    f.block_port(port)


def auto_sniff(f):
    while True:
        ip_to_ban, port_to_ban = get_suspicious()
        for ip in ip_to_ban:
            f.block_ip(ip)
        for port in port_to_ban:
            f.block_port(port)


def main():
    """
    Add Documentation here
    """
    # start iptables firewall
    t = IpTables()
    t.basic_protections()
    t.get_from_database()
    # Run protection algorithm
    algorithm = threading.Thread(target=auto_sniff, args=(t, TIME_TO_SNIFF, TIME_TO_SNIFF,))
    algorithm.setDaemon(True)
    algorithm.start()

    # run gui
    master = tk.Tk()
    master.minsize(width=400, height=300)
    ip_str = tk.StringVar()
    port_str = tk.StringVar()

    ip_entry = tk.Entry(master, textvariable=ip_str)
    ip_button = tk.Button(master, text="Ban IP", command=lambda: ban_by_ip(t, ip_str))
    ip_entry.pack()
    ip_button.pack()

    port_entry = tk.Entry(master, textvariable=port_str)
    port_button = tk.Button(master, text="Ban Port", command=lambda: ban_by_port(t, port_str))
    port_entry.pack()
    port_button.pack()

    master.mainloop()
    
    # restore iptables
    t.__del__()
    

if __name__ == '__main__':
    main()

