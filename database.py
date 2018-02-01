import sqlite3 as sql


IP_STRING = 0
PORT_NUM = 0


def execute_command(command, database, cursor):
    try:
        cursor.execute(command)
    except sql.OperationalError as e:
        return e
    database.commit()


class Database(object):
    def __init__(self, name):
        self.database = sql.connect(name)
        self.cursor = self.database.cursor()
        # Create tables
        sql_command = """CREATE TABLE IP (address char unique);
        """
        execute_command(sql_command, self.database, self.cursor)
        sql_command = "CREATE TABLE Ports (number int unique)"
        execute_command(sql_command, self.database, self.cursor)

    def add_ip(self, ip):
        sql_command = """INSERT OR IGNORE INTO IP (address) values (%s)""" % ip
        execute_command(sql_command, self.database, self.cursor)

    def add_port(self, port):
        sql_command = """INSERT OR IGNORE INTO Ports (number) VALUES (%d)""" % port
        execute_command(sql_command, self.database, self.cursor)

    def remove_ip(self, ip):
        sql_command = """DELETE FROM IP WHERE address == (%s)""" % ip
        execute_command(sql_command, self.database, self.cursor)

    def remove_port(self, port):
        sql_command = """DELETE FROM Ports WHERE number == (%d)""" % port
        execute_command(sql_command, self.database, self.cursor)

    def get_ip(self):
        sql_command = "SELECT * FROM IP"
        r = self.cursor.execute(sql_command)
        # organize results
        ip_list = []
        for row in r.fetchall():
            ip_list.append(row[IP_STRING])

        return ip_list

    def get_ports(self):
        sql_command = "SELECT * FROM Ports"
        r = self.cursor.execute(sql_command)
        # organize results
        port_list = []
        for row in r.fetchall():
            port_list.append(row[PORT_NUM])

        return port_list

