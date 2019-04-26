from ip_tables import IpTables
from algorithm import get_suspicious
import Tkinter as tk
import threading
import kivy
kivy.require('1.10.0')

from kivy.app import App
from kivy.uix.label import Label
from kivy.uix.gridlayout import GridLayout
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button


TIME_TO_SNIFF = 100
TEXT = 0
ACTION_ON_PRESS = 1


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


class SmallWindow(BoxLayout):
    def __init__(self, **kwargs):
        super(SmallWindow, self).__init__(orientation="vertical" ,**kwargs)
        for word, i in kwargs.iteritems():
            self.button = Button(text=kwargs[word][TEXT])
            self.button.bind(on_press=kwargs[word][ACTION_ON_PRESS])
            self.add_widget(self.button)


class Window(GridLayout):
    def __init__(self, **kwargs):
    	t = IpTables()
    	t.basic_protections()
        t.get_from_database()
    	# run algorithm
    	algorithm = threading.Thread(target=auto_sniff, args=(t, TIME_TO_SNIFF, TIME_TO_SNIFF))
        algorithm.setDaemon(True)
        algorithm.start()
        super(Window, self).__init__(**kwargs)
        self.cols = 3
        # ip
        self.add_widget(Label(text='IP'))
        self.ip = TextInput(multiline=False)
        self.add_widget(self.ip)
        self.ipwindow = SmallWindow(remove_url=("Remove URL/IP", lambda b: t.unblock_site(self.ip.text)), add_url=("Add URL/IP", lambda b: t.block_site(self.ip.text)))
        self.add_widget(self.ipwindow)
        # ports
        self.add_widget(Label(text='Port'))
        self.port = TextInput(multiline=False)
        self.add_widget(self.port)
        self.portwindow = SmallWindow(add=("Add Port", lambda b: t.block_port(self.port.text)), remove=("Remove Port", lambda b: t.unblock_port(self.port.text)))
        self.add_widget(self.portwindow)

class HelloKivy(App):
    def build(self):
        # Run protection algorithm
        return Window()

def main():
    """
    Add Documentation here
    """
    window = HelloKivy()
    window.run()

    # reset iptables
    IpTables().__del__()
    

if __name__ == '__main__':
    main()

