import unittest
import evmdasm

from binascii  import (hexlify, unhexlify)
from compiler import Artifact
from const    import opcode
from utils    import *

Instruction = evmdasm.Instruction

class SolidityBinary:

    rtcode: str = ""
    instructions: List[Instruction] = []

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

        SolidityBinary.instructions: List[Instruction] = list(evmdis.disassemble(self.rtcode))
        self.bytecode = unhexlify(self.rtcode)
        # logger.debug("\n" + "\n".join([str(i) for i in self.instructions]))
        # import pdb;pdb.set_trace()
    
    # TODO: move all evmdasm.Instruction as new class
    _instruction_cache = {} # dedicated cache for `instruction_at` function

    @classmethod
    def instruction_at(cls, addr: int) -> Instruction:
        '''
        found instruction at given address
        '''

        assert len(cls.instructions) != 0, "SolidityBinary isn't initialized"

        cache = cls._instruction_cache.get(addr)
        if cache is not None:
            return cache 
        
        for i in cls.instructions:
            if i.address == addr:
                cls._instruction_cache[addr] = i
                return i
            
        raise RuntimeError(f"Can't found instruction at pc: {hex(addr)}")
        
    @property
    def end_addr(self) -> int:
        '''
        find the last instruction's addr
        '''
        # TODO: opt here
        return max([i.address for i in self.instructions])
        
    def check_pc_jmp_valid(self, pc: int) -> bool:

        insts = self.instructions
        jumpdest = opcode.JUMPDEST
        
        # TODO: pc2inst repeat with instruction_at
        return pc <= self.end_addr and self.pc2inst(pc).opcode == jumpdest

    # TODO: opt here
    def pc2inst(self, pc: int) -> Instruction:
        for inst in self.instructions:
            if pc >= inst.address and pc < inst.address + inst.size:
                return inst
            
        raise RuntimeError(f"Can't found instruction at pc: {hex(pc)}")
