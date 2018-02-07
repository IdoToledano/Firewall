from setuptools import setup

setup(name='firewall',
	version='0.1',
	description='iptables firewall for linux',
	packages=['firewall',],
	install_requires=[
		'python-iptables', 'scapy',
	],
)
