'''
state window for execution display in terminal 
'''
import pyfiglet
import time

from vulns              import VulnTypes as V
from rich.console       import Console, Text
from vulns              import VULN_DESC
from assistant.observer import Observer
from datetime           import datetime 
from termcolor          import colored
from utils              import *

console = Console()

class StateWindow:

    __count_down = 8

    def __init__(self) -> None:
        now = datetime.now()
        # processing time
        self.create_time: str = now.strftime("%Y/%d/%m, %H:%M:%S")
        self.last_new_path_found: str = "None"
        self.last_vuln_found: str = "None"
        # state's status
        self.cur_state_count = 0
        self.total_state_count = 0
        # fuzzing status
        self.current_fuzzing_func = None # TODO:
        # coverage
        self.coverage_rate = 0.0 # TODO: make it remain decimal point
        # vulns found
        self.total_vulns_count = 0
        # device status
        self.cpu_utilization = None # TODO:
        # current evaluating constraint
        self.cur_evaluating_constraint = "None"
        self.average_constraint_eval_lapse = 0.00
        self.max_constraint_eval_lapse = 0.00

        self._vulns = {
            V.SELFDESTRUCT: colored("0", "green"),
            V.DELEGATECALL: colored("0", "green"),
            V.ARBITRARY_JUMP: colored("0", "green"),
        }

        pass
    
    def show_terminal(self, observer: Observer) -> None:

        try:

            if observer.debug:
                StateWindow.__count_down = 1
            
            self._show_terminal(observer)
            
        except KeyboardInterrupt:
            logger.debug("capture keyboard interrupt, return to main thread now...")
            return

    def _show_terminal(self, obs: Observer) -> None:

        while True:
            
            if not obs.debug:
                import os
                os.system("clear")

            result = pyfiglet.figlet_format("Warden", font="slant")
            result = "    " + "\n    ".join(result.split('\n'))
            rich_text = Text(result)
            rich_text.stylize("red")  # 在艺术字上应用彩色
            console.print(rich_text)

            # REF: https://coolsymbol.com/  https://www.alt-codes.net/
            print(
                f'{colored("processing time", "blue")} '                                       + '━' * 46 + '┓\n'
                f'┃        create time : {self.create_time:25s}'                               + ' ' * 14 + '┃\n'
                f'┃      last new path : {self.last_new_path_found:25s}'                       + ' ' * 14 + '┃\n'
                f'┃      last new vuln : {self.last_vuln_found:25s}'                           + ' ' * 14 + '┃\n'
                f'{colored("map coverage", "blue")} '                                          + '━' * 49 + '┫\n'
                f'┃      coverage rate : {self.coverage_rate:>4.0%}'                           + ' ' * 35 + '┃\n'
                f'{colored("cycle progress", "blue")} '                                        + '━' * 47 + '┫\n'
                f'┃   cur states count : {self.cur_state_count:>5}'                            + ' ' * 34 + '┃\n'
                f'┃ total states count : {self.total_state_count:>5}'                          + ' ' * 34 + '┃\n'
                f'{colored("vulnerability", "blue")} '                                         + '━' * 48 + '┫\n'
                f'┃  total vulns count : {self.total_vulns_count:>3}'                          + ' ' * 36 + '┃\n'
                f'┃ >\t{VULN_DESC[V.SELFDESTRUCT]}     : {self._vulns[V.SELFDESTRUCT]:}'       + ' ' * 34 + '┃\n'
                f'┃ >\t{VULN_DESC[V.DELEGATECALL]}     : {self._vulns[V.DELEGATECALL]:}'       + ' ' * 34 + '┃\n'
                f'┃ >\t{VULN_DESC[V.ARBITRARY_JUMP]}   : {self._vulns[V.ARBITRARY_JUMP]:}'     + ' ' * 34 + '┃\n'
                f'┗'                                                                           + '━' * 61 + '┛\n'
                f'current evaluating constraint : {self.cur_evaluating_constraint}\n'
                f'evaluating constraint average lapse: {self.average_constraint_eval_lapse}\n'
                f'evaluating constraint max lapse: {self.max_constraint_eval_lapse}\n'
            )

            time.sleep(0.5)

            if obs.has_new_path_found:
                self.last_new_path_found = datetime.now().strftime("%H:%M:%S")
            
            if obs.has_new_vuln_found:
                self.last_vuln_found = datetime.now().strftime("%H:%M:%S")

            self.cur_state_count = obs.cur_state_count

            self.coverage_rate = obs.coverage_rate

            self.total_vulns_count = obs.total_vulns_count

            self.total_state_count = obs.total_state_count

            self.cur_evaluating_constraint = obs.cur_evaluating_constraint

            self.average_constraint_eval_lapse = obs.average_constraint_eval_lapse
            self.max_constraint_eval_lapse = obs.max_constraint_eval_lapse


            for v in V:
                c = obs.vuln_count(v)
                self._vulns[v] = colored(str(c), "red" if c > 0 else "green")

            if obs.notify_statewindow_shutdown:
                self.__count_down -= 1
                if self.__count_down == 0:
                    break