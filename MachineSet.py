# This file use to define the set of fsm and recieve event.
from Event import Event
from machine import Machine

class MachineSet:
    def __init__(self, Machine=Machine):
        print("A new MachineSet has been defined.")
        # 目前是笨比设计，链表串起来
        self.root_fsm = Machine
        self.next_fsm = None

    def insert_fsm(self, Machine):
        self.next_fsm = Machine