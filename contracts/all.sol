// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.2 <0.9.0;

contract All {
    uint256 a;
    uint256 b;
    uint8[4] s;
    constructor() payable  {

    }

    function withdraw() private {
        require(msg.value == 0, 'dont send funds!');
        payable(msg.sender).transfer(address(this).balance);
    }
    
    function frwd() internal
        { withdraw(); }
    struct Func { function () internal f; }

    function vuln(address addr, uint256 va, uint256 selector, bytes calldata data) public payable {
        uint8[4] memory arr = [0x0d, 0x00, 0x07, 0x21];

        for(uint i = 0; i < s.length; i++) {
            s[i] = uint8(selector);
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
                selfdestruct(payable(0));
            }
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
            }
        }else {
            revert();
        }

    }
}