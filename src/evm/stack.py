from utils import *
from disassembler import SolidityBinary
import copy

class Stack:
    def __hash__(self) -> int:
        res = []
        for i in self.stack:
            res.append(hash(i))
        
        return hash(tuple(res))
        
    def __init__(self) -> None:
        # self.stack: List[T] = []
        self.stack: List[BV] = []
        self._debug_stack: List[str] = []

    def __getitem__(self, idx: int) -> BV:
        
        assert isinstance(idx, int)
        
        return self.stack[idx]

    def __setitem__(self, idx: int, val: BV) -> None:

        assert isinstance(idx, int)
        assert isinstance(val, BV)

        self.stack[idx] = val
        
    def __repr__(self) -> str:
        s = [""]
        end = len(self.stack) - 1
        i = end
        while i >= 0:
            if isinstance(self.stack[i], BV):
                r = "%#2x %s <- %s" % (end - i, self.stack[i], self._debug_stack[i])
            else:
                r = "%#2x %32x <- %s" % (end - i, self.stack[i], self._debug_stack[i])
            s.append(r)
            i -= 1

        return "\n".join(s)

    def dup(self, n: int) -> None:
        dup = self.stack[-n]
        dbg = self._debug_stack[-n]

        self.stack.append(dup)
        self._debug_stack.append(dbg)
    
    def swap(self, n: int) -> None:
        '''
        swap top element with (n+1)-depth element
        '''
        tmp = self.stack[-n-1]
        self.stack[-n-1] = self.stack[-1]
        self.stack[-1] = tmp

        tmp = self._debug_stack[-n-1]
        self._debug_stack[-n-1] = self._debug_stack[-1]
        self._debug_stack[-1] = tmp

    def pop(self, n=1) -> Union[BV, List[BV]]:
        '''
        return a pop list from top to end.
        e.g.
            stack = [1, 2, 3]
            stack.pop(2) = [3, 2]
        '''
        if n == 1:
            assert len(self.stack) > 0
            ret = self.stack.pop()
            self._debug_stack.pop()
            return ret
        
        ret = [self.stack.pop() for _ in range(n)] 
        [self._debug_stack.pop() for _ in range(n)] 

        return ret
    
    def push(self, s, e: Union[BV, int]) -> None:
        '''
        s: State
        '''
        if isinstance(e, BV):
            pass
        elif isinstance(e, int):
            e = BVVify(e)
        else:
            raise TypeError(f"push type: {type(e)}")

        self.stack.append(e)
        self._debug_stack.append(repr(SolidityBinary.instruction_at(s.pc)))
    
    def clone(self):
        return copy.deepcopy(self)

    def __len__(self) -> int:
        return len(self.stack)

    def __iter__(self):
        self.cur = len(self.stack) - 1  # 从堆栈顶部开始迭代
        return self

    def __next__(self):
        if self.cur >= 0:
            value = self.stack[self.cur]
            self.cur -= 1
            return value
        else:
            raise StopIteration