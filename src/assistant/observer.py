'''
the responsibility of observe the runtime infomations like coverage and bug collect.
handle data to screen printer
'''
from bugs import Bugs
from utils import *
from evm.state import State
from disassembler import Instruction
from collections import defaultdict
from copy import deepcopy

class Observer:
    # opt it with cfg coverage
    def __init__(self, all_instructions: List[Instruction]) -> None:
        self.bugs: Dict[Bugs, List[State]] = defaultdict(lambda: []) # TODO: vuln catalogue
        self._total_cov_count = len(all_instructions)
        self._coverage = {}

        for i in all_instructions:
            self._coverage[i.address] = 0
        
    new_path_found = False

    def hit_at(self, addr: int) -> None:

        assert isinstance(addr, int)
        
        # TODO: 这里没考虑循环路径信息
        if self._coverage[addr] == 0:
            new_path_found = True
        
        self._coverage[addr] += 1

    @property
    def has_new_path_found(self) -> bool:
        # refresh new path found every queries 
        if self.new_path_found:
            self.new_path_found = False
            return True
        
        return False
            

    @property
    def coverage_rate(self) -> float:

        hit_count = 0
        
        for k, v in self._coverage.items():
            if v > 0:
                hit_count += 1
                
        return hit_count / self._total_cov_count

    def add_a_bug(self, bug: Bugs, state: State) -> None:

        assert isinstance(bug, Bugs)
        
        self.bugs[bug].append(
            deepcopy(state)
        )