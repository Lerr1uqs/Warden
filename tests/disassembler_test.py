import unittest

class Disassembler(unittest.TestCase):
    # 一定要在开头加test 不然不会执行
    def test_instruction_and_cache(self):
        import sys
        sys.path.append("../src")
        # cat contracts/all/All.bin-runtime | evmasm -d
        from disassembler import SolidityBinary
        # from compiler import Artifact
        import sys
        sys.path.append("/home/squ/prac/warden/src")

        from src.compiler import Compiler
        comp = Compiler("./contracts")
        allvulns = comp["All"]

        sb = SolidityBinary(allvulns)
        self.assertEqual(sb.instruction_at(0x870).name, "CALLER")
        
        raised = False

        try:
            sb.instruction_at(0x870)
            sb.instruction_at(0x870)
            sb.instruction_at(0x870)
            sb.instruction_at(0x845)
            sb.instruction_at(0x7ec)
        except:
            raised = True
        
        self.assertFalse(raised, 'Exception raised')

# if __name__ == '__main__':
    # unittest.main()