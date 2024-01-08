# introduction
a simple demo solidity bytecode symbolic execute engine.
develop for Graduation Project in NUAA.

![](./assets/effect.png)
# 查看汇编
```shell
# squ @ squ-virtual-machine in ~/prac/warden [18:18:10] C:2
$ cat /home/squ/prac/soli-prac/contracts/ReentryProtected.bin | evmasm -d
00000000: PUSH1 0x80
00000002: PUSH1 0x40
00000004: MSTORE
00000005: CALLVALUE
00000006: DUP1
00000007: ISZERO
00000008: PUSH1 0xe
0000000a: JUMPI
0000000b: INVALID
0000000c: DUP1
0000000d: REVERT
```
# 生成opcodes
```shell
solc --opcodes --overwrite ./store.sol
```

# 关闭内存限制
```shell
ulimit -c unlimited
```

# ut
```shell
nosetests tests
```
notes that test function name must starts with "test_"

# TODO:
- [ ] 使用能够调度的queue
- [x] 更改环境 z3有问题
- [x] 增加一个状态显示 如果pc很久没更新了说不定就是正在约束求解
- [x] 调试模式
- [x] 降低耦合
- [x] 引入机制更改
- [x] 多函数序列调用 函数内部调用
- [x] 捕获编译输出
- [x] 避免重复编译
- [ ] argparse
- [x] 约束缓存
- [ ] 弄清段错误的位置
- [ ] 死区基本块优化
- [ ] 总用时
- [ ] 版本控制器和perf
- [ ] 漏洞detect模块化 分析状态
- [ ] 任意Storage写的判定 可能需要格外的一点heuristic的方法

# NOTE:
暂未考虑constructor, 因为这涉及到deploycode的初始化问题和调用序列生成这两块 还有最初的状态初始化，不过我心情好可能就写下把
# 论文idea
- [ ] 考虑求解的时机 没必要一直保持符号化约束 在某段事件之后可以将符号化转换为具体值