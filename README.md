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