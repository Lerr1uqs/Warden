import sys
import os

sys.path.append("./src")

from see          import SymExecEngine
from evm          import Contract
from loguru       import logger


os.system("echo '' > ./loguru.log")
logger.remove()
# logger.add(sys.stdout, level="INFO")
logger.add("loguru.log")


con = Contract("All")
# cfg = CFG(sb.bytecode) # TODO: runtime


SymExecEngine(con).execute()
