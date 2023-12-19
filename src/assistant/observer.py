'''
the responsibility of observe the runtime infomations like coverage and bug collect.
handle data to screen printer
'''
from vulns import VulnTypes
from utils import *
from evm.state import State
from disassembler import Instruction
from collections import defaultdict
from copy import deepcopy

class Observer:
    # opt it with cfg coverage
    def __init__(self, all_instructions: List[Instruction]) -> None:
        self._vulns: Dict[VulnTypes, List[State]] = defaultdict(lambda: []) # TODO: vuln catalogue
        self._total_cov_count = len(all_instructions)
        self._coverage = {}

        for i in all_instructions:
            self._coverage[i.address] = 0

    def vuln_count(self, v: VulnTypes) -> int:
        return len(self._vulns[v])
    
    @property
    def total_vulns_count(self) -> int:
        count = 0
        
        for k, v in self._vulns.items():
            count += len(v)
            
        return count
    
    _total_state_count = 0

    @property
    def total_state_count(self) -> int:
        return self._total_cov_count
    
    @total_state_count.setter
    def total_state_count(self, count: int) -> None:
        self._total_cov_count = count
    
    new_path_found = False

    def hit_at(self, addr: int) -> None:

        assert isinstance(addr, int)
        
        # TODO: 这里没考虑循环路径信息
        if self._coverage[addr] == 0:
            self.new_path_found = True
        
        self._coverage[addr] += 1

    @property
    def has_new_path_found(self) -> bool:
        # refresh new path found every queries 
        if self.new_path_found:
            self.new_path_found = False
            return True
        
        return False

    new_vuln_found = False

    @property
    def has_new_vuln_found(self) -> bool:
        # refresh new path found every queries 
        if self.new_vuln_found:
            self.new_vuln_found = False
            return True
        
        return False
    
    @property
    def coverage_rate(self) -> float:

        hit_count = 0
        
        for k, v in self._coverage.items():
            if v > 0:
                hit_count += 1
                
        return hit_count / self._total_cov_count

    def add_a_vuln(self, vuln: VulnTypes, state: State) -> None:

        assert isinstance(vuln, VulnTypes)
        
        self.new_vuln_found = True # update for query

        self._vulns[vuln].append(
            deepcopy(state)
        )