'''
constraints persistence to disk and load it for faster solve 
'''
import pickle
import os
 
from collections import defaultdict
from utils       import *

class ConstraintPersistor:

    CACHE_NAME = "constraints.cache"

    cache_enabled = True # disable for perf 
    
    def __init__(self) -> None:
        '''
        constraint persistence to storage
        '''


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

        # NOTE: maybe need delete cache file avoid collision in different contract fuzz?

        # first initialize
        cn = ConstraintPersistor.CACHE_NAME
        if (not os.path.exists(cn)) or (os.stat(cn).st_size == 0):
            with open(cn, 'w+b') as f:
                pickle.dump({}, f)

        with open(cn, 'r+b') as f:
            cache = pickle.load(f)

        self.satisfiable_cache: Dict[int, bool] = cache
    
    def add_constraint_cache(self, constraints: List[Type['claripy.Bool']], result: bool) -> None:

        if not all(isinstance(c, claripy.ast.bool.Bool) for c in constraints):
            raise TypeError
        
        # NOTE: the order for constraints is vital in hash search
        csts = sorted(constraints, key=lambda x: hash(x))

        self.satisfiable_cache[hash(tuple(csts))] = result
    
    def find_constraint_cache(self, constraints: List[Type['claripy.Bool']]) -> Optional[bool]:

        if not ConstraintPersistor.cache_enabled:
            return None

        if not all(isinstance(c, claripy.ast.bool.Bool) for c in constraints):
            raise TypeError
        
        csts = sorted(constraints, key=lambda x: hash(x))
        return self.satisfiable_cache.get(hash(tuple(csts)))
    
    def dump(self):
        '''
        dump the constraint cache to local storage
        '''
        with open(ConstraintPersistor.CACHE_NAME, 'w+b') as f:
            pickle.dump(self.satisfiable_cache, f)




cstpersistor = ConstraintPersistor()