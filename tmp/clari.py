from claripy import *
'''
[
    <Bool input-addr_1_256 == (0x0 .. input-addr_1_256[159:0])>, 
    <Bool input-uint256_3_256[31:24] == 13>, 
    <
        Bool (
            (if input-uint256_2_256 == 0x0 then 0x1 else 0x0) | 
            (if 0x2 * input-uint256_2_256 / input-uint256_2_256 == 0x2 then 0x1 else 0x0)
        ) == 0x0
    >
]
'''
a = BVS("uint256-a", 256)
b = BVS("uint256-b", 256)
c = BVS("uint256-c", 256)

BVV0 = BVV(0, 256)
BVV1 = BVV(1, 256)
BVV2 = BVV(2, 256)

solver = Solver()
solver.add(a == 0xffffffffffffffffffffffffffffffffffffffff & a)
solver.add(b[31:24] == 13)
e = c * 2 
e /= c
# 这个会特别慢
solver.add(
    If(c == BVV0, BVV1, BVV0) | If(e == BVV2, BVV1, BVV0) == 0
)

# a / b

# e = ((a * 2 + b - 3) / 2) % 2 == 0
import pdb;pdb.set_trace()
print(solver.constraints)
print("evaluating...")
solver.simplify()
solver.downsize()
print(solver.satisfiable())

# print(hash(tuple(solver.constraints)) & 0xffffffffffffffff)
# solver.constraints[2] = True
# print(solver.satisfiable())