from ip_tables import IpTables
from algorithm import get_suspicous_ips
import Tkinter as tk

TIME_TO_SNIFF = 3

def ban_by_ip(f, ip):
    ip = ip.get()
    f.block_ip(ip)


def ban_by_port(f, port):
    port = port.get()
    f.block_port(port)


def auto_sniff(f, time_to_sniff, time_str):
    time_int = int(time_str.get())
    done = False
    while not done:
        ip_to_ban = get_suspicous_ips(time_to_sniff)
	for ip in ip_to_ban:
	    print "{} is going to be banned!".format(ip)
	    f.block_ip(ip)
	    
	time_int -= time_to_sniff
	if (time_int <= 0):
	    done = True


def main():
    """
    Add Documentation here
    """
    t = IpTables()
    t.basic_protections()
    master = tk.Tk()

    ip_str = tk.StringVar()
    port_str = tk.StringVar()
    time_str = tk.StringVar()

    ip_entry = tk.Entry(master, textvariable=ip_str)
    ip_button = tk.Button(master, text="Ban IP", command=lambda: ban_by_ip(t, ip_str))
    ip_entry.pack()
    ip_button.pack()

    port_entry = tk.Entry(master, textvariable=port_str)
    port_button = tk.Button(master, text="Ban Port", command=lambda: ban_by_port(t, port_str))
    port_entry.pack()
    port_button.pack()

    start_entry = tk.Entry(master, text="Amount of time to sniff", textvariable=time_str)
    start_button = tk.Button(master, text="Start", command=lambda: auto_sniff(t, TIME_TO_SNIFF, time_str))
    start_entry.pack()
    start_button.pack()

    master.mainloop()

    

if __name__ == '__main__':
    main()
