import subprocess
import click
import time
import sys
import os

sys.path.append("./src")

from see          import SymExecEngine
from assistant    import DataAnalyzer
from assistant    import Observer
from evm          import Contract
from compiler     import Compiler
from loguru       import logger

from persistence  import ConstraintPersistor
from collections import defaultdict

os.system("echo '' > ./loguru.log")
logger.remove()
# logger.add(sys.stdout, level="INFO")
logger.add("loguru.log")


# compiler = Compiler("./contracts")
# 
# con = Contract("All")
# con = Contract("ArbiStorageWrite")
# con = Contract("ArbitraryJumpWithFuncSeqOrder")
# cfg = CFG(sb.bytecode) # TODO: runtime




@click.command()
@click.option('--debug', '-d', default=False, is_flag=True, help='enable debug mode')
@click.option('--enable-cache', '-e', default=False, is_flag=True, help='enable constrain cache mode')
@click.option('--not-logging', '-l', default=False, is_flag=True, help='enable the debug logger')
@click.option('--test-dir', '-p', type=click.Path(exists=True), help='test all contracts in given dir.')
@click.option('--contract', '-c', type=str, help="The name of the contract being executed")
@click.option('--benchmark', '-b', default=False, help="Whether enable benchmark with mythril")
def main(debug, enable_cache, not_logging, test_dir, contract, benchmark):

    if test_dir and contract:
        raise click.UsageError('Options --test-dir and --contract are mutually exclusive.')

    if (not test_dir) and (not contract):
        raise click.UsageError('Options --test-dir and --contract must select one')

    if debug:
        Observer.enable_debug()

    if not_logging:
        logger.remove()

    if not enable_cache:
        ConstraintPersistor.cache_enabled = False

    if not benchmark:

        if contract:
            con = Contract(contract)
            SymExecEngine(con).execute()
        else:
            compiler = Compiler(test_dir)
            da = DataAnalyzer()

            for conname, artifact in compiler.artifacts.items():
                logger.debug(f"current execute the {conname}")

                observer = SymExecEngine(Contract(artifact)).execute()
                
                da.add_contract_result(conname, observer)
                Observer.clean_vulnerabilies_data()

            logger.debug("fuzzing over")
            da.draw_vuln_catalog_histogram()

    else:
        if contract:
            raise NotImplementedError("only support batch benchmark")
        
        compiler = Compiler(test_dir)
        da = DataAnalyzer()

        # results[contract_name]["mythril" / "warden"] = time
        results = defaultdict(lambda : {})
        # myth_result[contract_name] = captured_result
        myth_result = {}

        for conname, artifact in compiler.artifacts.items():

            # ---------- warden test ---------------------
            path = compiler.contract_name_to_path(conname)
            logger.debug(f"current fuzzing the {path}")

            start = time.time()

            observer = SymExecEngine(Contract(artifact)).execute()
            
            da.add_contract_result(conname, observer)
            Observer.clean_vulnerabilies_data()

            end = time.time()
            elapsed = end - start

            results[conname]["warden"] = elapsed

            # ---------- mythril test ---------------------
            start = time.time()

            command = f"myth analyze {path}"
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                raise RuntimeError(f"mythril analyze {conname} failed with return code {result.returncode}")
            
            myth_result[conname] = result.stdout

            end = time.time()
            elapsed = end - start

            results[conname]["mythril"] = elapsed


        logger.debug("fuzzing over")
        for conname, res in results.items():
            sign = "<" if res['warden'] < res['mythril'] else ">"
            print(f"-----------------{conname}-------------------")
            print(f"warden: {res['warden']} {sign} mythril: {res['mythril']}")

        da.draw_vuln_catalog_histogram()



if __name__ == '__main__':
    main()

'''
py warden.py -d --test-dir ./contracts
py warden.py -d --contract All
'''