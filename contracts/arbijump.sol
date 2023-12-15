// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.2 <0.9.0;
// pragma solidity ^0.4.25;

contract ArbitraryJump {

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

    function breakIt() public payable {
        require(msg.value != 0, 'send funds!');

        Func memory func;
        func.f = frwd;

        uint256 v = msg.value;
        assembly { 
            mstore(func, v) // must be a JUMPDEST target 
        }
        func.f();
    }
}