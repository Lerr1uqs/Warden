from enum import Enum

class VulnTypes(Enum):
    SELFDESTRUCT = 1
    DELEGATECALL = 2
    ARBITRARY_JUMP = 3

VULN_DESC = {
    VulnTypes.SELFDESTRUCT: "selfdestruct",
    VulnTypes.DELEGATECALL: "delegatecall",
    VulnTypes.ARBITRARY_JUMP: "arbitrary jump",
}
