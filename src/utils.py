# external
from loguru import logger
from typing import (Callable, Optional, TypeVar, List, Tuple, Type, Dict, Any, Union, Set, Generic, Sequence)
import claripy
import numbers
from pydantic import BaseModel
CONCRETE = numbers.Number# TODO
# internal
from disassembler import (SolidityBinary)
from evm.contract import Contract
from evm.state    import State

class Todo:
    def __init__(self) -> None:
        raise Exception("TODO")
    
    # TODO:
class MultipleSolutionsError(ValueError):
    pass

bvv = lambda v : claripy.BVV(v, 256)
# bvs = lambda v : claripy.BVS(v, 256)

BVV0 = bvv(0)
BVV1 = bvv(1)
BV = claripy.ast.BV

# TEMP: temporary
EXP_EXPONENT_FUZZ = {min, max}
def Sha3(x):# TODO:
    return claripy.BV("SHA3", [x], length=256)

DEFAULT_ADDRESS = claripy.BVV(0xffffffffffffffffffffffffff, 256)
DEFAULT_CALLER = claripy.BVV(0xCAFEBABEFFFFFFFFF0202FFFFFFFFF7CFF7247C9, 256)
# TODO: 账户地址最多20bytes 而不是32
ATTACK_ACCOUNT_ADDRESS = claripy.BVV(0x0d000721_0d000721_0d000721_0d000721_0d000721, 256)