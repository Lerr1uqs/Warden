from utils import *
import const
import evmdasm
from binascii import (hexlify, unhexlify)

class SolidityBinary:

    code: str = ""
    
    def __init__(self, filename: str) -> None:
        with open(filename, 'r') as file:
            bin = file.read()
            self.code = bin

        # TODO: remove it
        # if bin.startswith("0x"):
        #     bin = bin[2:]
        # bin = unhexlify(bin)

        evmdis = evmdasm.EvmDisassembler()

        self.instructions: List[evmdasm.Instruction] = list(evmdis.disassemble(bin))
        self.bytecode = unhexlify(bin)
        logger.debug("\n" + "\n".join([str(i) for i in self.instructions]))
        # import pdb;pdb.set_trace()

    def check_pc_jmp_valid(self, pc: int) -> bool:

        insts = self.instructions
        jumpdest = const.opcode.JUMPDEST
        
        return pc < len(insts) and self.pc2inst(pc).opcode == jumpdest

    # TODO: opt here
    def pc2inst(self, pc: int) -> evmdasm.Instruction:
        for inst in self.instructions:
            if pc >= inst.address and pc < inst.address + inst.size:
                return inst
            
        raise NotImplementedError