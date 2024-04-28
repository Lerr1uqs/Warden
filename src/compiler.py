'''
solidity compiler, based on local solc 
'''
import subprocess
import shutil
import solcx
import json
import os

from collections import defaultdict, deque
from copy        import deepcopy
from binascii    import unhexlify
from pathlib     import Path
from web3        import Web3
from utils       import *

import networkx as nx

def bfs(root: dict) -> List[str]:

    queue = deque([root])
    res   = []

    while len(queue) != 0:

        e = queue.popleft()
        
        if type(e) in [int, str, bool]:
            continue

        elif type(e) == list:
            for i in e:
                queue.append(i)

        elif type(e) == dict:

            if e.get("nodeType") and e["nodeType"] == "Identifier":
                res.append(e["name"])

            else:
                for k, v in e.items():
                    queue.append(v)
        else:
            raise TypeError(f"unhandled type{type(e)}")


    return res



class Artifact:
    def __init__(self, rtbc: str, initbc: str, json_obj: List[Dict], ast: Dict) -> None:
        self.rtbc   = rtbc
        self.initbc = initbc
        self.abi    = json_obj
        self.ast    = ast
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

        # handle the function input info
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

        # handle ast info
        # REF: assets/ast.json

        # the variable declared in the storage region
        # NOTE: 目前简单采用同名去辨别变量 更复杂的情况需要区别重命名 暂时不做处理
        storage_variable_names: Set[str] = set()

        # dfa[fname]["w/r"] = List[var_name]
        dfa: Dict[str, Dict[str, Set[str]]] = defaultdict(lambda: defaultdict(lambda: set()))

        for node in ast["nodes"]:
            if node["nodeType"] == "ContractDefinition":
                nodes = node["nodes"]
                break

        for node in nodes:
            
            if node["nodeType"] == "VariableDeclaration":
                storage_variable_names.add(node["name"])
                # print(f'[DBG] storage_variable_names append {node["name"]}')
                continue

            if node["nodeType"] == "FunctionDefinition":

                fname = node["name"]
                # TEMP: skip constructor currently
                if node["kind"] == "constructor":
                    continue

                # NOTE: I assume the term `statemen` is content of one line, but I can't found enough material to prove that
                # leftExpression 和 rightExpression是嵌套的 不过做DFA只需要
                # NOTE: the function `selfdestruct` also be conceived as `Identifier` in ast... 
                try:
                    if not node.get("body"):
                        # interface funtion have no body
                        continue

                    for statement in node["body"]["statements"]:
                        if statement["nodeType"] == "ExpressionStatement":
                            expression = statement["expression"]

                            if expression["nodeType"] == "Assignment":
                                if name := expression["leftHandSide"].get("name"):
                                    # e.g. a = 1 + 2
                                    dfa[fname]["w"].add(name)
                                else:
                                    # e.g. func.f = 1                                
                                    name = expression["leftHandSide"]["expression"]["name"]
                                    dfa[fname]["w"].add(name)

                                # print(f'[DBG] dfa[{fname}][\"w\"] append {name}')
                                dfa[fname]["r"].update(bfs(expression["rightHandSide"]))
                            else:
                                dfa[fname]["r"].update(bfs(expression))

                        else:
                            dfa[fname]["r"].update(bfs(statement))
                except KeyError as ke:
                    # for DEBUG
                    raise ke
                    import json
                    p = lambda js: print(json.dumps(js, indent=2))
                    import pdb; pdb.set_trace()
                
        # only remain the storage function name
        for fname in dfa.keys():
            dfa[fname]["r"].intersection_update(storage_variable_names)
            dfa[fname]["w"].intersection_update(storage_variable_names)

        self.dfa = dfa

        graph = nx.DiGraph()
        # fnames = []

        # all function nodes
        # for fname in dfa.keys():
            # filted internal function like fallback withdraw etc.
        for fname in self.funcnames:
            graph.add_node(fname)
                # fnames.append(fname)

        # build the topology graph
        for fname in self.funcnames:
            for var in dfa[fname]["w"]:
                for otherf in self.funcnames:
                    if otherf == fname:
                        continue
                    if var in dfa[otherf]["r"]:
                        # means F(fname) write a var which F(otherf) read
                        graph.add_edge(fname, otherf) # fname -> otherf

        # self.ftopo_graph = graph # function topology graph

        # 划分为联通分量
        connected_components = list(nx.connected_components(graph.to_undirected()))
        
        # 将联通分量转为列表
        subgraphs: List[nx.DiGraph] = [graph.subgraph(component) for component in connected_components]

        # NOTE: shallow copy : each_indegree = [{}] * len(subgraphs) # fname -> indegree
        # calculate the oreder sequence according indegree
        each_indegree = [deepcopy({}) for _ in range(len(subgraphs))]  # fname -> indegree

        for fname in self.funcnames:
            # TODO: removed NOTE: I skips some function that don't affect the storage state

            #       cuz I only analyze the state of a possible attack and not replicate the attack itself(e.g. actual transfer to attck)
            # if graph.in_degree(fname) == 0 and graph.out_degree(fname) == 0:
            #     continue
            # TODO: 暂时跳过 readme 解释
            for i, sg in enumerate(subgraphs):
                if fname in sg.nodes:
                    each_indegree[i][fname] = sg.in_degree(fname)
                    break


        '''
        for example
        indegree[f1] = 1
        indegree[f2] = 3
        indegree[f3] = 1
        indegree[f4] = 2
        indegree[f5] = 1

        so as result:
        function_seq_order = [
            [f1, f3, f5],
            [f4],
            [f2]
        ]
        '''
        def find_keys(d: Dict, target_v) -> List:
            res = []
            for k, v in d.items():
                if v == target_v:
                    res.append(k)

            return res

        # fso[subgraph_idx][indegree] = [fname ...]
        function_seq_order: List[List[List[str]]] = [deepcopy([]) for _ in range(len(subgraphs))]

        try:
            for i, indegree in enumerate(each_indegree):
                for j in range(0, max(indegree.values())+1):
                    fname_list = find_keys(indegree, j)
                    function_seq_order[i].append(fname_list)
    
        except ValueError as e:
            # not function depend on each other
            raise e
        
        self.fseqorder = function_seq_order # have possibility of empty


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
    

    def contract_name_to_path(self, conname: str) -> str:
        return self.cname2path[conname]


    def __init__(self, contracts_path: Union[Path, str]) -> None:
        '''
        REFINE: https://web3py.readthedocs.io/en/v5/contracts.html
        '''
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
        
        self.cname2path = {}

        self.artifacts: Dict[str, Artifact] = {} # contract name -> Bytecode

        for file in sol_files:

            import pdb; pdb.set_trace()

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

            result = subprocess.run([
                    'solc', 
                    '--bin-runtime', 
                    '--bin', 
                    '--opcodes', 
                    '--abi', 
                    '--overwrite',
                    '--ast-compact-json',
                    os.path.join(con_path, file), # e.g. contracts/selfdestruct.sol
                    '-o', 
                    folder_path
                ],
                stdout = subprocess.DEVNULL,
                stderr = subprocess.STDOUT
            )
            
            if result.returncode != 0:
                raise RuntimeError(f"solc failed with return code {result.returncode}")

            cnwps = set() # skip processed artifact files
            contract_names = set() # prevent same-name contract

            # Traverse through the files in the folder generated by each sol file
            for fpath in Path(folder_path).rglob("*"):
                # logger.debug(fpath)
                
                output_filename = os.path.basename(fpath) # e.g. ArbitraryJump.bin

                if output_filename.endswith(".ast"):
                    # output_filename is different from others 
                    continue
                
                contract_name = output_filename.split('.')[0] # e.g. ArbitraryJump
                self.cname2path[contract_name] = file

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

                ast_path = folder_path + "/" + file.split(".")[0]
                with open(ast_path + ".sol_json.ast", "r") as f:
                    ast = json.load(f)
                # NOTE: opcodes file? not in use at present

                if contract_name in contract_names:
                    raise RuntimeError(f"contract {output_filename} appear many times")

                self.artifacts[contract_name] = Artifact(rtbc, initbc, abi, ast)
                
                cnwps.add(cnwp)
                    
                        
        