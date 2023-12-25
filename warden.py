import os
import sys
sys.path.append("./src")

from typing import Dict
from see import SymExecEngine
from disassembler import SolidityBinary
from evm.contract import Contract


import subprocess as sp

from loguru import logger
os.system("echo '' > ./loguru.log")
logger.remove()
# logger.add(sys.stdout, level="INFO")
logger.add("loguru.log")

from compiler import Compiler
comp = Compiler("./contracts")
allvulns = comp["All"]

# path = "./store.bin"
# TODO: pythonpath env var
sb = SolidityBinary(allvulns)# TODO:
con = Contract(sb)# TODO: remove sb to contract
# cfg = CFG(sb.bytecode) # TODO: runtime


see = SymExecEngine(sb, con)
try:
    see.execute()
    # print("\n".join(see.tracer))
except Exception as e:
    # print("\n".join(see.tracer))
    raise e
    
# from evm.state import STATE_COUNTER
# print(f"state counter = {STATE_COUNTER}")