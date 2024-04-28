from disassembler import Instruction
from utils import *

class CFG:
    def __init__(self, insts: List[Instruction]) -> None:
        pass

    def is_dead_basicblock(self, addr: int) -> bool:
        return False