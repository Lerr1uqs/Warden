from claripy import *

a = BVV(1, 256)
b = BVS("b", 256)

solver = Solver()
solver.add(a != b)
res = solver.solution(b == 2, b < 3)

assert res == True

res = solver.eval(b, n=5)
print(res)