// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.2 <0.9.0;
// pragma solidity ^0.4.25;

contract ArbitraryJumpWithFuncSeqOrder {
    uint256 a;
    uint256 b;
    constructor() payable { 
        require(msg.value != 0); 
    }

    function withdraw() private {
        require(msg.value == 0, 'dont send funds!');
        payable(msg.sender).transfer(address(this).balance);
    }

    function frwd() internal
        { withdraw(); }

    struct Func { function () internal f; }

    function first() public {
        a = 0x0d00;
    }
    function second() public {
        b = 0x0721;
    }

    function third() public payable {
        require(a == 0x0d00 && b == 0x0721, 'require function call order');

        Func memory func;
        func.f = frwd;

        uint256 v = msg.value;
        assembly { 
            mstore(func, v) // must be a JUMPDEST target 
        }
        func.f();
    }
}