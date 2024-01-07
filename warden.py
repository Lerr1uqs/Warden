import sys
import os

sys.path.append("./src")

from see          import SymExecEngine
from assistant    import Observer
from evm          import Contract
from loguru       import logger


os.system("echo '' > ./loguru.log")
logger.remove()
# logger.add(sys.stdout, level="INFO")
logger.add("loguru.log")

Observer.enable_debug()

# con = Contract("All")
con = Contract("ArbitraryJumpWithFuncSeqOrder")
# cfg = CFG(sb.bytecode) # TODO: runtime


SymExecEngine(con).execute()
