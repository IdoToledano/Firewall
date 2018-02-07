from database import *

d = Database("firewall.db")
d.remove_ip("255.255.255.255")
