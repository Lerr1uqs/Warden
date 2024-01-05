'''
solidity compiler, based on local solc 
'''
import subprocess
import shutil
import json
import os

from collections import defaultdict
from binascii    import unhexlify
from pathlib     import Path
from web3        import Web3
from utils       import *



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

        # not contain constructor
        self.funcs: Dict[str, Dict] = {}
        
        # not contain constructor
        self.funcnames: List[str] = []

        # not contain constructor
        self.signatures: Dict[str, int] = {} # func name -> signature

        # contain constructor
        self.func_input_types: Dict[str, List] = defaultdict(lambda: [])

        for func in json_obj:

            if func["type"] == "constructor":

                self.constructor: Dict = func
                
                function_input_types = []
                for i in range(len(func['inputs'])):
                    input_type = func['inputs'][i]['type']
                    function_input_types.append(input_type)

                self.func_input_types["constructor"] = function_input_types
                
            elif func["type"] in ["fallback", "receive"]:
                # NOTE: not take into consideration at present
                pass
            else:
                assert func["type"] == "function"

                fname = func['name']
                function_input_types = []
                signature = fname + '('

                for i in range(len(func['inputs'])):

                    input_type: str = func['inputs'][i]['type']
                    function_input_types.append(input_type)
                    signature += input_type
                    
                    if i < len(func['inputs']) - 1:
                        signature += ','
                        
                signature += ')'

                hash = Web3.keccak(text=signature)[0:4].hex()

                self.funcnames.append(fname)
                self.signatures[fname] = hash
                self.funcs[fname] = func
                self.func_input_types[fname] = function_input_types

class Compiler:

    def contract_artifact(self, conname) -> Artifact:
        '''
        get a contract artifact by name
        '''
        return self[conname]

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

        # get all .sol files at specific path
        sol_files = [
            f 
            for f in os.listdir(con_path) 
            if os.path.isfile(os.path.join(con_path, f)) and f.endswith('.sol')
        ]

        self.artifacts: Dict[str, Artifact] = {} # contract name -> Bytecode

        for file in sol_files:

            folder_name = file.split('.')[0]
            folder_path = os.path.join(con_path, folder_name)

            # create if not exist
            if not os.path.exists(folder_path):
                os.makedirs(folder_path)

            # complie the .sol file to artifacts
            '''
            generate 4 files:
                Storage.bin Storage.abi Storage.bin-runtime  Storage.opcode
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
                ],
                stdout = subprocess.DEVNULL,
                stderr = subprocess.STDOUT
            )

            cnwps = set() # skip processed artifact files
            contract_names = set() # prevent same-name contract

            # Traverse through the files in the folder generated by each sol file
            for fpath in Path(folder_path).rglob("*"):
                # logger.debug(fpath)
                
                output_filename = os.path.basename(fpath) # e.g. ArbitraryJump.bin

                contract_name = output_filename.split('.')[0] # e.g. ArbitraryJump

                # contract name with path but not suffix
                cnwp = Path(fpath).absolute().__str__().split('.')[0] # e.g. /xxx/contracts/delegatecall/Attack

                if cnwp in cnwps:
                    continue
                
                with open(cnwp + ".bin", "r") as f:
                    initbc = f.read()
                        
                with open(cnwp + ".bin-runtime", "r") as f:
                    rtbc = f.read()

                with open(cnwp + ".abi", "r") as f:
                    abi = json.load(f)
                
                # NOTE: opcodes file? not in use at present
                
                if contract_name in contract_names:
                    raise RuntimeError(f"contract {output_filename} appear many times")

                self.artifacts[contract_name] = Artifact(rtbc, initbc, abi)
                
                cnwps.add(cnwp)
                    
                        
        