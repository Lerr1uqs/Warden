from utils import *
import copy

BV = claripy.ast.BV

# storage的粒度比memory更细 是对slot进行265位的处理的
class Storage:
    def __init__(self, address: int) -> None:
        # TODO:
        assert isinstance(claripy.BVV(1, 256), BV)
        self._slots: Dict[CONCRETE, BV] = {}

        # Stores all keys already set in the storage
        self._indexes_set: Set[BV] = set()

        # Stores all get already keys in the storage
        self._indexes_get: Set[BV] = set()

        self.address = address

    def __getitem__(self, idx: Union[BV, CONCRETE]) -> BV:

        # if type(idx) == CONCRETE:
        #     idx = bvv(idx)
        assert isinstance(idx, BV)
        
        slots = self._slots
        self._indexes_get.add(idx)

        if idx.symbolic:
            # means I can found a arbitrary slot write?
            logger.warning("TODO")
            ...

        return claripy.simplify(slots[idx])# TODO: what?
    
    # TODO: 类型
    def __setitem__(self, idx, value: Union[BV, claripy.ast.Bool]) -> None: # TODO:类型
        if isinstance(value, claripy.Bool):
            value = claripy.If(value, 1, 0)

        
        self._slots[value] = value
        self._indexes_set.add(idx)

    def clone(self):
        return copy.deepcopy(self)

    
