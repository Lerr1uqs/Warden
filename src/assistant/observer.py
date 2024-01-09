'''
the responsibility of observe the runtime infomations like coverage and bug collect.
handle data to screen printer
'''
from vulns import VulnTypes
from utils import *
from see.state import State
from disassembler import Instruction
from collections import defaultdict
from copy import deepcopy

class Observer:

    __debug = False

    stop = False
    
    @classmethod
    def enable_debug(cls) -> None:
        cls.__debug = True

    @property
    def debug(self) -> bool:
        return Observer.__debug
    
    # opt it with cfg coverage
    def __init__(self, all_instructions: List[Instruction]) -> None:
        self._vulns: Dict[VulnTypes, List[State]] = defaultdict(lambda: [])
        self._total_cov_count                     = len(all_instructions)
        self._coverage                            = {}
        self.notify_statewindow_shutdown          = False

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
    
    __total_state_count = 0

    @property
    def total_state_count(self) -> int:
        return Observer.__total_state_count
    
    @total_state_count.setter
    def total_state_count(self, count: int) -> None:
        Observer.__total_state_count = count

    __cur_state_count = 0

    @property
    def cur_state_count(self) -> int:
        return Observer.__cur_state_count
    
    @cur_state_count.setter
    def cur_state_count(self, count: int) -> None:
        Observer.__cur_state_count = count
    
    __new_path_found = False

    def hit_at(self, addr: int) -> None:

        assert isinstance(addr, int)
        
        # TODO: 这里没考虑循环路径信息
        if self._coverage[addr] == 0:
            Observer.__new_path_found = True
        
        self._coverage[addr] += 1

    @property
    def has_new_path_found(self) -> bool:
        # refresh new path found every queries 
        if Observer.__new_path_found:
            Observer.__new_path_found = False
            return True
        
        return False

    __new_vuln_found = False

    @property
    def has_new_vuln_found(self) -> bool:
        # refresh new path found every queries 
        if Observer.__new_vuln_found:
            Observer.__new_vuln_found = False
            return True
        
        return False
    
    @property
    def coverage_rate(self) -> float:

        hit_count = 0
        
        for k, v in self._coverage.items():
            if v > 0:
                hit_count += 1
                
        return hit_count / self._total_cov_count

    '----------------------------------VULN CATALOG----------------------------------------'

    __vuln_at_pc = [] # avoid repeat vulns 

    @property
    def vulnerabilities(self) -> Dict[VulnTypes, int]:
        
        vulns = {}
        
        for t in VulnTypes:
            vulns[t] = len(self._vulns[t])

        return vulns

    def add_a_vuln(self, vuln: VulnTypes, state: State) -> None:

        assert isinstance(vuln, VulnTypes)

        if state.pc in Observer.__vuln_at_pc:
            return
        
        Observer.__vuln_at_pc.append(state.pc)
        
        Observer.__new_vuln_found = True # update for query

        self._vulns[vuln].append(
            deepcopy(state)
        )

    @classmethod
    def clean_vulnerabilies_data(cls) -> None:
        cls.__vuln_at_pc = []

    '---------------------------------------------------------------------------------'

    __cur_evaluating_constraint = "None"
    __cur_evaluating_state = "Run Symbolic Engine..."

    @property
    def cur_evaluating_constraint(self):
        return Observer.__cur_evaluating_constraint
    
    @cur_evaluating_constraint.setter
    def cur_evaluating_constraint(self, constraint: str):

        if not isinstance(constraint, str):
            raise TypeError
        Observer.__cur_evaluating_state = "Constraint Evaluating..."
        Observer.__cur_evaluating_constraint = constraint
    
    __per_constraint_eval_lapses = []

    def notify_constraint_eval_over(self, lapse: float) -> None:
        Observer.__per_constraint_eval_lapses.append(lapse)
        Observer.__cur_evaluating_constraint = "None"
        Observer.__cur_evaluating_state = "Run Symbolic Engine..."

    @property
    def cur_evaluating_state(self) -> str:
        return Observer.__cur_evaluating_state

    # notes: timing the evaluation is the role of StateWindow cuz it is independent thread

    @property
    def average_constraint_eval_lapse(self) -> float:

        total = sum(Observer.__per_constraint_eval_lapses)
        size = len(Observer.__per_constraint_eval_lapses)
        
        return total / size
    
    @property
    def max_constraint_eval_lapse(self) -> float:

        return max(Observer.__per_constraint_eval_lapses)


class ConstraintEvalNotifier:
    '''
    facilitate to communicate with observer
    '''
    def __init__(self, obs: Observer, constraint: Union[List[Type['claripy.Bool']], Type['claripy.Bool']]):

        from time import perf_counter
        
        self.obs = obs
        self.cst = constraint
        self.pc  = perf_counter
    
    def __enter__(self):
        self.start = self.pc()
        self.obs.cur_evaluating_constraint = str(self.cst)
        return self

    def __exit__(self, type, value, traceback):
        self.lapse = self.pc() - self.start
        self.obs.notify_constraint_eval_over(self.lapse)
        