from .stack import Stack

class Opcode:
    ...


class Call(Opcode):
    def __init__(self, stack: Stack) -> None:
        assert stack is not None

        [   self.gas, 
            self.addr, 
            self.val, 
            self.argOst, 
            self.argLen, 
            self.retOst, 
            self.retLen
        ] = stack.pop(7)

        super().__init__()