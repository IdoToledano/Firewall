from ip_tables import IpTables
from algorithm import get_suspicous_ips
import Tkinter as tk
import threading

TIME_TO_SNIFF = 100

def ban_by_ip(f, ip):
    ip = ip.get()
    f.block_ip(ip)


def ban_by_port(f, port):
    port = port.get()
    f.block_port(port)


def auto_sniff(f, time_to_sniff, time_str):
    time_int = time_str
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

    master.mainloop()
    
	# restore iptables
    t.__del__()
    

if __name__ == '__main__':
    main()

