# -*- coding: utf-8 -*-
class IP:
    """
    Holds important information about the requests that the specified ip address had requested.
    """
    totalCount = 0

    def __init__(self, ip, frequency):
        self.ip = ip
        self.delta_time = frequency
        self.count = 0
        self.velocity = 0
        self.delta_velocity = 0
        self.acceleration = 0

    def add_count(self, num):
        self.count += num
        self.calc_velocity(num)
        IP.totalCount += num

    def calc_velocity(self, num):
        self.delta_velocity = (num / self.delta_time) - self.velocity
        self.velocity += self.delta_velocity
        self.calc_acceleration()

    def calc_acceleration(self):
        self.acceleration = self.delta_velocity / self.delta_time

    def get_data(self):
        return {"ip": self.ip, "velocity": self.velocity, "acceleration": self.acceleration}
