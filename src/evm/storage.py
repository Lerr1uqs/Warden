from utils import *
import copy

BV = claripy.ast.BV
from numbers import Integral
from collections import defaultdict

# storage的粒度比memory更粗 是对slot进行265位的处理的
class Storage:
    def __init__(self, address: int) -> None:
        # debug for storage allow uninit read
        self._slots: Dict[int, BV] = defaultdict(lambda: BVV0)

        # Stores all keys already set in the storage
        self._indexes_set: Set[int] = set()

        # Stores all get already keys in the storage
        self._indexes_get: Set[int] = set()

        self.address = address

    def __hash__(self) -> int:

        if len(self._indexes_get) == 0:
            return 0
        
        max_index = max(self._indexes_set)
        res = []
        
        for i in range(0, max_index+1):
            slot = self._slots[i]
            res.append(hash(slot))
        
        return hash(tuple(res))


    def __getitem__(self, idx: BV) -> BV:

        if not isinstance(idx, BV):
            raise TypeError

        slots = self._slots
        # self._indexes_get.add(idx.concrete_value) 

        if idx.symbolic:
            # means I can found a arbitrary slot read?
            raise NotImplementedError("arbitrary slot read") # TODO: easy to check this vuln
        else:
            if isinstance(idx.concrete_value, bool):
                raise NotImplementedError
                idx = 1 if idx.concrete_value else 0
            elif isinstance(idx.concrete_value, int):
                idx = idx.concrete_value
            else:
                raise TypeError(f"unhandled {type(idx.concrete_value)}")

        assert isinstance(idx, int)

        return claripy.simplify(slots[idx])
    
    def __setitem__(self, idx: BV, value: BV) -> None:

        if not isinstance(idx, BV):
            raise TypeError
        
        if idx.symbolic: 
            raise NotImplementedError("arbitrary slot write") # TODO:

        # if isinstance(value, claripy.ast.Bool):
            # raise NotImplementedError
            value = claripy.If(value, BVV1, BVV0)

        elif isinstance(idx.concrete, int):
            idx = idx.concrete_value
        else:
            raise TypeError(f"unhandled {type(idx.concrete_value)}")
        
        self._slots[idx] = value
        self._indexes_set.add(idx)

    def __repr__(self) -> str:
        r = ""
        for k, v in self._slots.items():
            r += f"{k} {v}\n"
        return r

    def clone(self):
        return copy.deepcopy(self)

    
