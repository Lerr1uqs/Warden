from see import SymExecEngine
from disassembler import SolidityBinary
from evm.contract import Contract

from typing import Dict
import sys


import subprocess as sp

from loguru import logger
logger.remove()
logger.add(sys.stdout, level="INFO")

from compiler import Compiler
comp = Compiler("./contracts")
selfdestruct = comp["SelfDestruct"]

# path = "./store.bin"
# TODO: pythonpath env var
sb = SolidityBinary(selfdestruct)# TODO:
con = Contract(sb)# TODO: remove sb to contract
# cfg = CFG(sb.bytecode) # TODO: runtime


see = SymExecEngine(sb, con)
try:
    see.execute()
    print("\n".join(see.tracer))
except Exception as e:
    print("\n".join(see.tracer))
    raise e
    
from evm.state import STATE_COUNTER
print(f"state counter = {STATE_COUNTER}")