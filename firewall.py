from ip_tables import IpTables
from algorithm import get_suspicous_ips
import Tkinter as tk

def ban_by_ip(f, ip):
    ip = ip.get()
    f.block_ip(ip)

def ban_by_port(f, port):
    port = port.get()
    f.block_port(port)

def auto_sniff(f, time_to_sniff):
    try:
        f.basic_protections()
        while True:
            ip_to_ban = get_suspicous_ips(time_to_sniff)
	    for ip in ip_to_ban:
		print "{} is going to be banned!".format(ip)
		f.block_ip(ip)
    finally:
        f.reset_iptables()


def main():
    """
    Add Documentation here
    """
    t = IpTables()
    try:
	time_to_sniff = float(raw_input("Enter frequency of sniffing (in seconds, default is 3): "))
    except Exception:
	time_to_sniff = 3

    master = tk.Tk()

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

    start_button = tk.Button(master, text="Start", command=lambda: auto_sniff(t, time_to_sniff))
    start_button.pack()

    master.mainloop()

    

if __name__ == '__main__':
    main()
