import click
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
def main(debug, enable_cache, not_logging, test_dir, contract):

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


if __name__ == '__main__':
    main()

'''
py warden.py -d --test-dir ./contracts
py warden.py -d --contract All
'''