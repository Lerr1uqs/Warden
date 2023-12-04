from utils import *
import secrets



    
class Contract:
    def __init__(self) -> None:
        # self.caller  = Todo()
        self.address         = secrets.token_hex(32) #Todo()
        self.balance         = 10 #Todo()
        self.block_timestamp = 1  # Todo()
        self.block_number    = 1  #Todo
        self.chainid         = 1  #Todo