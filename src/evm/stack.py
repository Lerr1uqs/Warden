from utils import *
import copy

BV = claripy.ast.BV
T = TypeVar("T")

class Stack(Generic[T]):
    stack: List[T] = []
    def __init__(self) -> None:
        # self.stack: List[T] = []
        ...

    def __repr__(self) -> str:
        s = [""]
        end = len(self.stack) - 1
        i = end
        while i >= 0:
            if isinstance(self.stack[i], BV):
                r = "%#2x %s" % (end - i, self.stack[i])
            else:
                r = "%#2x %32x" % (end - i, self.stack[i])
            s.append(r)
            i -= 1

        return "\n".join(s)


    def pop(self, n=1) -> Union[T, List[T]]:
        '''
        返回一个栈顶到栈底的pop列表
        '''
        if n == 1:
            assert len(self.stack) > 0
            ret = self.stack.pop()
            return ret
        
        ret = [self.stack.pop() for _ in range(n)] 
        return ret
    
    def push(self, e: T) -> None:
        self.stack.append(e)
    
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
    # TODO: provide a idx select