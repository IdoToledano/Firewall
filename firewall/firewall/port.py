# -*- coding: utf-8 -*-
class Port:
    """
    Holds important information about the requests that the specified port num had requested.
    """

    def __init__(self, port, frequency):
	self.port = port
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
        return {"port": self.port, "velocity": self.velocity, "acceleration": self.acceleration}
