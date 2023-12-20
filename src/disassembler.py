from utils import *
import const
import evmdasm
from binascii import (hexlify, unhexlify)
from compiler import Artifact

Instruction = evmdasm.Instruction

class SolidityBinary:

    rtcode: str = ""
    instructions: List[evmdasm.Instruction] = []

    def __init__(self, artifact: Artifact) -> None:
        # with open(filename, 'r') as file:
            # bin = file.read()
            # self.code = bin
        self.artifact = artifact
        self.rtcode = artifact.rtbc # TEMP: 

        # TODO: remove it
        # if bin.startswith("0x"):
        #     bin = bin[2:]
        # bin = unhexlify(bin)

        evmdis = evmdasm.EvmDisassembler()

        SolidityBinary.instructions: List[evmdasm.Instruction] = list(evmdis.disassemble(self.rtcode))
        self.bytecode = unhexlify(self.rtcode)
        # logger.debug("\n" + "\n".join([str(i) for i in self.instructions]))
        # import pdb;pdb.set_trace()
    
    # TODO: move all evmdasm.Instruction as new class
    @classmethod
    def instruction_at(cls, addr: int) -> evmdasm.Instruction:
        # TODO: opt here
        for i in cls.instructions:
            if i.address == addr:
                return i
            
        raise NotImplementedError(f"unreachable with {hex(addr)}")
        
    @property
    def end_addr(self) -> int:
        '''
        find the last instruction's addr
        '''
        # TODO: opt here
        return max([i.address for i in self.instructions])
        
    def check_pc_jmp_valid(self, pc: int) -> bool:

        insts = self.instructions
        jumpdest = const.opcode.JUMPDEST
        
        # TODO: pc2inst repeat with instruction_at
        return pc <= self.end_addr and self.pc2inst(pc).opcode == jumpdest

    # TODO: opt here
    def pc2inst(self, pc: int) -> evmdasm.Instruction:
        for inst in self.instructions:
            if pc >= inst.address and pc < inst.address + inst.size:
                return inst
            
        raise NotImplementedError