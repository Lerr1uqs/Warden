import copy

from evm import Stack, Contract, opcode, Memory, Storage
from utils import *

BV = claripy.ast.BV

STATE_COUNTER = 1

class State:
    def __init__(self, con: Contract) -> None:
        '''
        Represents a state during the execution of a contract.
        '''
        self.contract                 = con
        self.pc                       = 0
        self.stack                    = Stack()
        self.memory                   = Memory()
        self.depth                    = 0
        self.storage                  = Storage(con.address)
        self.solver                   = claripy.Solver()
        self.calls: List[opcode.Call] = []

        # executed pc addr
        self.exec_addrs = []
    
    # DEBUG aimed
    def print_exec_trace(self) -> None:
        print("---------------------------------------")
        for addr in self.exec_addrs:
            inst = self.contract.sb.instruction_at(addr)
            print(f"{hex(addr)} {inst}")
        print("---------------------------------------")
        
    def __repr__(self) -> str:
        return (
            "State(\n"
            "\tpc = %x\n"
            "\tstorage = %s\n"
            ")"
        ) % (
            self.pc,
            self.storage,
        )
    
    def clean(self):
        '''
        NOTE: 
        '''
        self.stack.clean()
        self.memory.clean()
        # NOTE: storage?
        self.solver.downsize() # Clears all caches associated with this backend.

    def __hash__(self):

        l = [
            hash(self.contract),
            hash(self.pc),
            hash(self.memory), 
            hash(self.storage),
            hash(self.stack)
        ]

        x = 0
        for constraint in self.solver.constraints:
            x ^= hash(constraint)

        l.append(x)
        
        return hash(tuple(l))

    def stack_push(self, x: BV):
        if len(self.stack) >= 1024:
            raise RuntimeError("Stack overflow") # NOTE
        self.stack.push(self, x)
    
    def stack_dup(self, n: int) -> None:
        self.stack.dup(n)

    def stack_swap(self, n: int) -> None:
        self.stack.swap(n)
        
    def stack_pop(self, n=1) -> Union[List[BV], BV]:
        return self.stack.pop(n)

    def clone(self):
        """Make a shallow copy of the current environment. Needs to be fast."""
        new_state                 = State(self.contract)
        new_state.pc              = self.pc
        new_state.stack           = self.stack.clone()
        new_state.memory          = self.memory.clone()
        # new_state.storage_written = self.storage_written.copy()
        # new_state.storage_read = self.storage_read.copy()
        new_state.storage         = self.storage.clone()
        new_state.solver          = copy.deepcopy(self.solver)
        new_state.calls           = self.calls[:]
        new_state.depth           = self.depth
        new_state.exec_addrs      = copy.deepcopy(self.exec_addrs)

        global STATE_COUNTER
        STATE_COUNTER += 1
        
        return new_state
    
    @DeprecationWarning
    def find_one_solution(self, var: BV) -> BV:
        solutions = self.solver.eval(var, 2)
        if len(solutions) > 1:
            raise SymbolicMultiSolutions
        logger.debug(type(solutions))
        return solutions[0] # TODO:solution的类型
