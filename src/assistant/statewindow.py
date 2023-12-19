'''
state window for execution display in terminal 
'''

from assistant.observer import Observer
import time
from termcolor import colored
from datetime import datetime 


class StateWindow:

    def __init__(self) -> None:
        now = datetime.now()
        # processing time
        self.create_time: str = now.strftime("%Y/%d/%m, %H:%M:%S")
        self.last_new_path_found: str = "None"
        self.last_vuln_found: str = "None"    # TODO: unique vuln
        # state's status
        self.total_state_count = 0
        # fuzzing status
        self.current_fuzzing_func = None # TODO:
        # coverage
        self.coverage_rate = 0.0 # TODO: query observer
        # vulns found

        # device status
        self.cpu_utilization = None # TODO:

        pass
    
    def show_terminal(self, observer: Observer) -> None:
        try:
            self._show_terminal(observer)
        except KeyboardInterrupt:
            import sys
            sys.exit(0)
    
    def _show_terminal(self, observer: Observer) -> None:

        while True:

            # REF: https://coolsymbol.com/  https://www.alt-codes.net/
            print(
                f'{colored("processing time", "blue")}━━━━━━━━━━━━━━━━━━━━━━━━━━━┓'
                f'┃       create time : {self.create_time:25s}                        ┃'
                f'┃     last new path : {self.last_new_path_found:25s}                  ┃'
                f'┃     last new vuln : {self.last_vuln_found:25s}                  ┃'
                f'┃total states count : {self.total_state_count:>20}                  ┃'
                f'┃     coverage rate : {self.coverage_rate:>20}                  ┃'
                f'┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛'
            )

            time.sleep(0.5)

            if observer.has_new_path_found:
                self.last_new_path_found = datetime.now().strftime("%H:%M:%S")
            
            if observer.has_new_vuln_found:
                self.last_vuln_found = datetime.now().strftime("%H:%M:%S")

            self.total_state_count = observer.total_state_count

            self.coverage_rate = observer.coverage_rate

        
    