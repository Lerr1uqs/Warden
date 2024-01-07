from enum import Enum

class Stage(Enum):
    MID_TERM = 0
    FINIAL_TERM = 1

class VersionControl:
    '''
    paper version control for perf 
    '''
    def __init__(self, ver: Stage) -> None:
        self.version = ver
    
    @property
    def current_version(self) -> Stage:
        return self.version
    