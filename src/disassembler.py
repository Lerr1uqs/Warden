import unittest
import evmdasm

from binascii  import (hexlify, unhexlify)
from compiler import Artifact
from const    import opcode
from utils    import *

Instruction = evmdasm.Instruction

class SolidityBinary:

    instructions: List[Instruction] = []
    
    def __init__(self, artifact: Artifact) -> None:

        self.artifact = artifact
        self.rtcode = artifact.rtbc

        evmdis = evmdasm.EvmDisassembler()

        SolidityBinary.instructions: List[Instruction] = list(evmdis.disassemble(self.rtcode))
        self.bytecode = unhexlify(self.rtcode)

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
        
    _end_instruction_address = None # dedicated cache for `end_addr` property

    @property
    def end_addr(self) -> int:
        '''
        find the last instruction's addr
        '''
        if self._end_instruction_address:
            return self._end_instruction_address
        
        self._end_instruction_address = max([i.address for i in self.instructions])
        return self._end_instruction_address
        
    def check_pc_jmp_valid(self, pc: int) -> bool:

        jumpdest = opcode.JUMPDEST
        
        return pc <= self.end_addr and self.instruction_at(pc).opcode == jumpdest

