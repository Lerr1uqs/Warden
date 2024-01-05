'''
constraints persistence to disk and load it for faster solve 
'''
from collections import defaultdict
from utils       import *

class ConstraintPersistor:
    def __init__(self) -> None:
        '''
        >>> a = BVS("b", 256)
        >>> hash(a)
        -7116667571479737063
        >>> hash(a) & 0xffffffffffffffff
        11330076502229814553
        >>> hex(hash(a) & 0xffffffffffffffff)
        '0x9d3c848ca9688d19'

        BVS hash is 64-byte
        '''

        '''
        >>> s.add(a < 1)
        (<Bool b_1_256 < 0x1>,)
        >>> type(s.constraints[0])
        <class 'claripy.ast.bool.Bool'>
        '''

        # NOTE: 对每一个约束的hash判断是不是satisfiable
        # TODO: 但是是不是要对当前的状态进行检测呢？
        self.satisfiable_cache: Dict[int, bool] = {}
    
    def add_constraint_cache(self, constraint: claripy.Bool, result: bool) -> None:

        if not isinstance(constraint, claripy.Bool):
            raise TypeError
            
        self.satisfiable_cache[hash(constraint)] = result
    
    def find_constraint_cache(self, constraint: claripy.Bool) -> Optional[bool]:

        if not isinstance(constraint, claripy.Bool):
            raise TypeError
        
        return self.satisfiable_cache.get(hash(constraint))


cstpersistor = ConstraintPersistor()