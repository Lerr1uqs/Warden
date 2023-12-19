'''
state window for execution display in terminal 
'''

class StateWindow:

    def __init__(self) -> None:
        # processing time
        self.create_time
        self.last_new_path
        self.last_vuln_found # TODO: unique
        # state's status
        self.total_state_count
        # fuzzing status
        self.current_fuzzing_func
        # coverage
        self.coverage_rate # TODO: query observer
        # vulns found

        # device status
        self.cpu_utilization

        pass
        
    