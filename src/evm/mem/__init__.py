from utils import *
# WARN: deprecated
@DeprecationWarning
class Slot:
    '''
    provide slots r/w method for Memory/Storage
    '''

    _slot: Dict[int, List[BV]] = {}
    _have_writen = []
    _have_read   = []
    # TODO: explain super.__init__
    def __init__(self) -> None:
        pass

    # def read(self, slot_idx: int, )