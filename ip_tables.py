# -*- coding: utf-8 -*-
import iptc
from socket import gethostbyname
from database import Database


# chains
INPUT = 0
OUTPUT = 1
FORWARD = 2


class IpTables(object):

    @staticmethod
    def _default_policy(chains):
        """
        Changes policy of all chains to drop except
        for the output chain
        """
        chains[INPUT].set_policy("DROP")
        chains[OUTPUT].set_policy("ACCEPT")
        chains[FORWARD].set_policy("DROP")

    @staticmethod
    def _accept_all(chains):
        """
        Incase Drop all made you lose your music from youtube.
        Change all policies to accept all traffic
        """
        chains[INPUT].set_policy("ACCEPT")
        chains[OUTPUT].set_policy("ACCEPT")
        chains[FORWARD].set_policy("ACCEPT")

    @staticmethod
    def _allow_loopback(chains):
        """
        Adds rule to allow all traffic between self and self
        """
        rule = iptc.Rule()
        rule.in_interface = "lo"
        target = iptc.Target(rule, "ACCEPT")
        rule.target = target
        chains[INPUT].insert_rule(rule)

    @staticmethod
    def _allow_established(chains):
        """
        Adds rule to allow established and related
        connections.
        (connections that I created and connections
         that are created by those)
        """
        rule = iptc.Rule()
        match = rule.create_match('state')
        match.state = "RELATED,ESTABLISHED"
        rule.target = iptc.Target(rule, 'ACCEPT')
        chains[INPUT].insert_rule(rule)

    def __init__(self):
        # set firewall's table as the Filter table
        self.table = iptc.Table(iptc.Table.FILTER)

        # create each chain
        chain_input = iptc.Chain(self.table, "INPUT")
        chain_output = iptc.Chain(self.table, "OUTPUT")
        chain_forward = iptc.Chain(self.table, "FORWARD")
        self.chains = [chain_input, chain_output, chain_forward]
        # initiate firewall database
        self.database = Database("firewall.db")

    def __del__(self):
        self.reset_iptables()

    def get_from_database(self):
        # initiate from database
        ip_list = self.database.get_ip()
        for ip in ip_list:
            self.block_ip(ip)

        port_list = self.database.get_port()
        for port in port_list:
            self.block_port(port)

    def basic_protections(self):
        """
        Sets up basic firewall protections.
        """
        IpTables._default_policy(self.chains)
        IpTables._allow_loopback(self.chains)
        IpTables._allow_established(self.chains)

    def block_ip(self, ip):
        """
        Given and Ip, blocks the ip from all traffic (in or out)
        """
        rule = iptc.Rule()
        # in case ip is invalid
        try:
            rule.set_src(ip)
        except Exception as e:
            return 1, e

        rule.create_target("DROP")
        self.chains[INPUT].insert_rule(rule)

        # add ip address to database
        self.database.add_ip(ip)

        return 0, ""

    def block_port(self, port):
        """
        Given a port, blocks the port from all traffic
        """
        for proto in ["tcp", "udp"]:
            rule = iptc.Rule()

            rule.protocol = proto
            match = rule.create_match(proto)
            # in case the port is invalid
            try:
                match.sport = str(port)
            except Exception as e:
                return 1, e

            rule.create_target("DROP")
            self.chains[INPUT].insert_rule(rule)

        # add port to database
        self.database.add_port(int(port))

        return 0, ""

    def block_site(self, site_name):
        """
        Given a site name, finds the sites ip
        and blocks the ip from all traffic
        """
        try:
            ip = gethostbyname(site_name)
        except Exception as e:
            return 1, e

        IpTables.block_ip(self, ip)

        return 0, ""

    def unblock_ip(self, ip):
        """
        Unblocks the given Ip if it was blocked

        Returns exception and 1 when the rule
        did not exist in the chain and 0
        when there wasn't any exception
        """
        rule = iptc.Rule()
        rule.set_src(ip)
        rule.create_target("DROP")

        # If ip isn't in chain
        try:
            self.chains[INPUT].delete_rule(rule)
        except Exception as e:
            return 1, e

        # remove from database
        self.database.remove_ip(ip)

        # return with no errors
        return 0, ""

    def unblock_port(self, port):
        """
        Unblock a port

        Returns exception and 1 when the rule
        did not exist in the chain and 0
        when there wasn't any exception
        """
        for proto in ["tcp", "udp"]:
            rule = iptc.Rule()

            rule.protocol = proto
            match = iptc.Match(rule, proto)
            # in case the port is invalid
            try:
                match.sport = str(port)
            except Exception as e:
                return 1, e

            rule.create_target("DROP")

            # if rule isn't in chain
            try:
                self.chains[INPUT].delete_rule(rule)
            except Exception as e:
                return 1, e

        # remove from database
        self.database.remove_port(int(port))

        # return with no errors
        return 0, ""

    def unblock_site(self, site_name):
        """
        finds ip of given site and unblocks it if
        it was in the chain.
        """
        # in case the host name is invalid or doesn't exist
        try:
            ip = gethostbyname(site_name)
        except Exception as e:
            return 1, e

        # unblock the found ip
        self.unblock_ip(ip)
        return 0, ""

    def reset_iptables(self):
        """
        Resets iptables to their original state.
        No rules or extra tabels, all packet counters
        are reset.
        """
        # Let everything in
        IpTables._accept_all(self.chains)
        # clear all rules
        self.table.flush()
        # zero all packet and byte counters
        self.table.zero_entries("OUTPUT")
        self.table.zero_entries("INPUT")
        self.table.zero_entries("FORWARD")
