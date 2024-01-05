from utils import *
import copy

BV = claripy.ast.BV
from numbers import Integral
from collections import defaultdict

# storage的粒度比memory更细 是对slot进行265位的处理的
class Storage:
    def __init__(self, address: int) -> None:
        # TODO:
        assert isinstance(claripy.BVV(1, 256), BV)
        # debug for storage allow uninit read
        self._slots: Dict[int, BV] = defaultdict(lambda: BVV0)

        # Stores all keys already set in the storage
        self._indexes_set: Set[int] = set()

        # Stores all get already keys in the storage
        self._indexes_get: Set[int] = set()

        self.address = address

    def __hash__(self) -> int:

        max_index = max(self._indexes_set)
        res = []
        
        for i in range(0, max_index+1):
            slot = self._slots
            res.append(hash(slot))
        
        return hash(tuple(res))


    def __getitem__(self, idx: Union[BV, int]) -> BV:

        # if type(idx) == CONCRETE:
        #     idx = bvv(idx)
        assert isinstance(idx, BV)
        assert idx.concrete, repr(idx)
        
        slots = self._slots
        # self._indexes_get.add(idx.concrete_value) TODO:

        if idx.symbolic:
            # means I can found a arbitrary slot write?
            raise NotImplementedError("TODO")
        else:
            if isinstance(idx.concrete, bool):
                idx = 1 if idx.concrete_value else 0
            elif isinstance(idx.concrete, int):
                idx = idx.concrete_value

        assert isinstance(idx, int)

        logger.debug(slots)
        return claripy.simplify(slots[idx])# TODO: what?
    
    # TODO: 类型
    # TOOD:
    def __setitem__(self, idx: Union[BV, Integral], value: Union[BV, claripy.ast.Bool]) -> None: # TODO:类型

        assert isinstance(value, BV)

        if isinstance(value, claripy.ast.Bool):
            value = claripy.If(value, BVV1, BVV0)

        # TODO: 转换函数
        assert idx.concrete
        # if isinstance(idx, BV):
        #     assert idx.concrete
        #     idx = idx.concrete_value
        if isinstance(idx.concrete, bool):
            idx = 1 if idx.concrete_value else 0
        elif isinstance(idx.concrete, int):
            idx = idx.concrete_value
        else:
            raise TypeError(f"unhandled {type(idx.concrete_value)}")
        
        self._slots[idx] = value
        self._indexes_set.add(idx.concrete_value)

    def __repr__(self) -> str:
        r = ""
        for k, v in self._slots.items():
            r += f"{k} {v}\n"
        return r

    def clone(self):
        return copy.deepcopy(self)

    
