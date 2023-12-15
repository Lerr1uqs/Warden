from see import SymExecEngine
from disassembler import SolidityBinary
from evm.contract import Contract

from evm_cfg_builder.cfg import CFG, BasicBlock
from typing import Dict
import sys


import subprocess as sp
path = "./store.bin"
# TODO: pythonpath env var
sb = SolidityBinary(path)# TODO:
con = Contract()# TODO: remove sb to contract
cfg = CFG(sb.bytecode) # TODO: runtime

bbs: Dict[int, BasicBlock] = getattr(cfg, "_basic_blocks")# dict[addr, BasicBlock]
for (pc, bb) in bbs.items():
    print(f"bb at {pc}")
    ...
sys.exit(0)

see = SymExecEngine(sb, con)
try:
    see.execute()
    print("\n".join(see.tracer))
except Exception as e:
    print("\n".join(see.tracer))
    raise e
    
from evm.state import STATE_COUNTER
print(f"state counter = {STATE_COUNTER}")