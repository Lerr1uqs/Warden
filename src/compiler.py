'''
solidity compiler, based on local solc 
'''
from pathlib import Path
import os
import subprocess
import re
import shutil

from binascii import unhexlify

from utils import *

from collections import defaultdict
import json

class Artifact:
    def __init__(self, rtbc: str, initbc: str, json_obj: List[Dict]) -> None:
        self.rtbc = rtbc
        self.initbc = initbc
        self.abi = json_obj
        '''
        [
            {
                'inputs': [], 
                'stateMutability': 'payable', 
                'type': 'constructor'
            }, 
            {
                'inputs': [
                    {
                        'internalType': 'address', 
                        'name': 'addr', 
                        'type': 'address'
                    }, 
                    {
                        'internalType': 'bytes', 
                        'name': 'data', 
                        'type': 'bytes'
                    }
                ], 
                'name': 'Func', 
                'outputs': [], 
                'stateMutability': 'nonpayable', 
                'type': 'function'
            }, 
            {
                'inputs': [], 
                'name': 'withdraw', 
                'outputs': [], 
                'stateMutability': 'nonpayable', 
                'type': 'function'
            }
        ]
        '''

        self.funcs: Dict[str, Dict] = {}
        self.funcnames: List[str] = []

        for func in json_obj:

            if func["type"] == "constructor":
                self.constructor: Dict = func
            elif func["type"] in ["fallback", "receive"]:
                # TODO: 暂时不纳入考虑
                pass
            else:
                self.funcs[func["name"]] = func

class Compiler:

    def __getitem__(self, conname: str) -> Artifact:
        '''
        conname: contract name
        '''
        return self.artifacts[conname]


    def __init__(self, contracts_path: Union[Path, str]) -> None:

        if isinstance(contracts_path, str):
            contracts_path = Path(contracts_path)
        
        assert isinstance(contracts_path, Path)

        con_path: Path = contracts_path

        # 获取指定路径下的所有.sol文件
        sol_files = [
            f 
            for f in os.listdir(con_path) 
            if os.path.isfile(os.path.join(con_path, f)) and f.endswith('.sol')
        ]

        # self.artifacts: Dict[str, Artifact] = defaultdict(lambda: Artifact()) # contract name -> Bytecode
        self.artifacts: Dict[str, Artifact] = {} # contract name -> Bytecode

        for file in sol_files:
            # 创建文件夹，如果已存在则删除
            folder_name = file.split('.')[0]
            folder_path = os.path.join(con_path, folder_name)

            if os.path.exists(folder_path):
                shutil.rmtree(folder_path)

            os.makedirs(folder_path)


            # 编译.sol文件
            '''
            generate 3 files:
                Storage.bin  Storage.bin-runtime  Storage.opcode
            '''

            logger.info("compiling sol files...")

            subprocess.run([
                'solc', 
                '--bin-runtime', 
                '--bin', 
                '--opcodes', 
                '--abi', 
                '--overwrite',
                os.path.join(con_path, file), # e.g. contracts/selfdestruct.sol
                '-o', 
                folder_path
            ])

            cnwps = set() # skip processed artifact files
            contract_names = set() # prevent same-name contract

            # 遍历每个sol文件产生的文件夹里面的文件
            for fpath in Path(folder_path).rglob("*"):
                # logger.debug(fpath)
                
                output_filename = os.path.basename(fpath) # e.g. ArbitraryJump.bin

                contract_name = output_filename.split('.')[0] # e.g. ArbitraryJump

                # contract name with path but not suffix
                # cnwp only appear
                cnwp = Path(fpath).absolute().__str__().split('.')[0] # e.g. /xxx/contracts/delegatecall/Attack

                if cnwp in cnwps:
                    continue
                
                with open(cnwp + ".bin", "r") as f:
                    initbc = f.read()
                        
                with open(cnwp + ".bin-runtime", "r") as f:
                    rtbc = f.read()

                with open(cnwp + ".abi", "r") as f:
                    abi = json.load(f)
                
                if contract_name in contract_names:
                    raise RuntimeError(f"contract {output_filename} appear many times")

                self.artifacts[contract_name] = Artifact(rtbc, initbc, abi)
                
                cnwps.add(cnwp)
                    
                # NOTE: opcodes file?
                        
        