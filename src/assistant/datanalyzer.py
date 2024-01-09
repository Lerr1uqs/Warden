from vulns import VulnTypes
from collections import defaultdict
# from .observer import Observer
from copy      import deepcopy
from utils     import *
class Observer:
    pass

import numpy as np
import matplotlib.pyplot as plt

def default_dict() -> Dict[VulnTypes, int]:

    d = {}
    
    for t in VulnTypes:
        d[t] = 0

    return d

class DataAnalyzer:
    '''
    for paper data analyze and handle
    '''

    def __init__(self) -> None:
        self.catalog: Dict[str, Dict[VulnTypes, int]] = {}
    
    def add_contract_result(self, contract_name: str, obs: Type['Observer']) -> None:
        self.catalog[contract_name] = deepcopy(obs.vulnerabilities)

    def debug_simulate_result(self) -> None:
        self.catalog["a"] = default_dict()
        self.catalog["bb"] = default_dict()
        self.catalog["ccc"] = default_dict()
        self.catalog["dddd"] = default_dict()

        self.catalog["a"][VulnTypes.ARBITRARY_JUMP] = 2
        self.catalog["a"][VulnTypes.SELFDESTRUCT] = 1

        self.catalog["bb"][VulnTypes.ARBITRARY_SLOT_WRITE] = 4
        self.catalog["bb"][VulnTypes.ARBITRARY_JUMP] = 2
        self.catalog["bb"][VulnTypes.SELFDESTRUCT] = 1

        self.catalog["ccc"][VulnTypes.DELEGATECALL] = 1
        self.catalog["ccc"][VulnTypes.ARBITRARY_JUMP] = 2
        self.catalog["ccc"][VulnTypes.SELFDESTRUCT] = 3

        self.catalog["dddd"][VulnTypes.DELEGATECALL] = 4

    def draw_vuln_catalog_histogram(self) -> None:

        contract_names = self.catalog.keys()

        count: Dict[int, List[int]] = {} # count[int(VULN TYPE)] = List[count of each contract's this vuln]
        for t in VulnTypes:
            
            cs = []
            
            for cname in contract_names:
                cs.append(self.catalog[cname][t])
                
            count[t.value] = cs
            assert len(cs) == len(contract_names)

        
        width = 0.15
        gap = 0.1  # 两组之间的间隔
        x = np.arange(len(contract_names))

        for i, vt in enumerate(VulnTypes):
            plt.bar(x + i * width, count[vt.value],  width=width, label=vt.name)

        plt.xticks(x + (len(VulnTypes) - 1) * width / 2, contract_names, rotation=25, ha='right')
        # 设置 y 轴刻度标签为整数
        plt.yticks(np.arange(0, max(max(cs) for cs in count.values()) + 1, step=1))
        # 设置 y 轴范围为整数
        plt.ylim(0, max(max(cs) for cs in count.values()) + 1)

        # 调整底部空间
        plt.subplots_adjust(bottom=0.2) 
        plt.legend()
        plt.savefig('result.png')

if __name__ == "__main__":
    da = DataAnalyzer()
    da.debug_simulate_result()
    da.draw_vuln_catalog_histogram()