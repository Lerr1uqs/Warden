from see import SymExecEngine
from disassembler import SolidityBinary
from evm.contract import Contract

path = "./store.bin"
# TODO: pythonpath env var
sb = SolidityBinary(path)# TODO:
con = Contract()# TODO: remove sb to contract

see = SymExecEngine(sb, con)
try:
    see.execute()
    print("\n".join(see.tracer))
except Exception as e:
    print("\n".join(see.tracer))
    raise e
    
from evm.state import STATE_COUNTER
print(f"state counter = {STATE_COUNTER}")