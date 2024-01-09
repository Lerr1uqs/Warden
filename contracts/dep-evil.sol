// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.2 <0.9.0;

contract DepEvil {
    uint256 _dep0 = 0;
    uint256 _dep1 = 0;
    uint256 _dep2 = 0;

    uint256 a;
    uint256 b;
    uint8[4] s;
    constructor() payable  {

    }

    function frwd() internal {}

    struct Func { function () internal f; }

    function dep0(uint256 input) public {
        // 如果这里依赖于_dep1/2的话就fuzz不出来了 因为数据流依赖的算法不完备
        require(_dep0 == 0);
        _dep0 = (input * 2) & 0xffff ^ 0x8766 ^ 0x2887;
    }

    function dep1(uint256 input) public {
        require(_dep0 != 0);
        _dep1 = input & 0x0d00;
    }

    function dep2(uint256 input) public {
        require(_dep0 != 0);
        _dep2 = input & 0x0721;
    }

    function evil(address addr, uint256 va, uint256 selector, bytes calldata data) public payable {
        require(_dep1 * _dep2 > 114514);
        uint8[4] memory arr = [0x0d, 0x00, 0x07, 0x21];

        for(uint i = 0; i < s.length; i++) {
            s[s.length - i - 1] = uint8(selector);
            selector = selector >> 8;
        }

        if(s[0] == arr[0]) {
            a = va * 2 + 1;
            uint256 c = va + 4;
            if(c % 2 == 0) {
                if (a == 0x0d000721){
                    selfdestruct(payable(addr));
                }
            }else {
                // avoid this state
                if (a == 0x0d000721){
                   selfdestruct(payable(0));
                }
            }
            selfdestruct(payable(addr));
        }
        else if(s[1] == arr[1]) {
            Func memory func;
            func.f = frwd;

            uint256 v = msg.value;
            assembly { 
                mstore(func, v) // must be a JUMPDEST target 
            }
            func.f();

        }else if(s[2] == arr[2]) {
            if(s[3] ^ arr[3] == 0) {
                addr.delegatecall(data);
            } else {
                Func memory func;
                func.f = frwd;

                uint256 v = msg.value;
                assembly { 
                    mstore(func, v) // must be a JUMPDEST target 
                }
                func.f();
            }
        }else {
            selfdestruct(payable(addr));
        }

    }
}