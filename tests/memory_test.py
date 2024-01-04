import unittest
import claripy


class MemoryTest(unittest.TestCase):
    def test_memory(self):
        from evm.memory import Memory

        m = Memory()
        a = claripy.BVV(0xffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff, 256)
        b = claripy.BVV(0xffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff, 256)
        h = claripy.BVV(0xffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_11111111, 256 + 8 * 4)
        c = claripy.BVV(0x11111111_00000000_00000000_00000000_00000000_00000000_00000000_00000000, 256)
        d = claripy.BVV(0x11111111_22222222_33333333_44444444, 128)
        e = claripy.BVV(0x11111111_22222222_33333333_44444444_ffffffff_ffffffff_ffffffff_ffffffff, 256)
        f = claripy.BVV(0x11111111_22222222_33333333_44444444_55555555_66666666_77777777_88888888_11111111_22222222_33333333_44444444, 256 + 128)
        g = claripy.BVV(0x11111111_22222222_33333333_44444444_55555555_66666666_77777777_88888888, 256)
        l = claripy.BVV(0x11111111_11111111_11111111_11111111_11111111_11111111_11111111_11111111, 256)
        i = claripy.BVV(0xffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_ffffffff_11111111, 256)
        j = claripy.BVV(0xffffffff_ffffffff_ffffffff_11111111_11111111_11111111_11111111_11111111, 256)


        m.write(0 * 0x20, 32, a)
        self.assertEqual(
            m.read(0, 32).concrete_value,
            b.concrete_value
        )

        m.write(0 * 0x20, 32 + 4, h)
        self.assertEqual(
            m.read(1 * 0x20, 32).concrete_value,
            c.concrete_value
        )


        m.write(0 * 0x20, 32, a)
        m.write(0 * 0x20, 16, d)
        self.assertEqual(
            m.read(0 * 0x20, 32).concrete_value,
            e.concrete_value
        )

        m.write(0 * 0x20, 32, a)
        m.write(1 * 0x20, 32, a)
        m.write(0 * 0x20, 48, f)
        self.assertEqual(
            m.read(0 * 0x20, 32).concrete_value,
            g.concrete_value
        )
        self.assertEqual(
            m.read(1 * 0x20, 32).concrete_value,
            e.concrete_value
        )

        m.write(0 * 0x20, 32, a)
        m.write(1 * 0x20, 32, a)
        m.write(28, 32, l)
        self.assertEqual(
            m.read(0 * 0x20, 32).concrete_value,
            i.concrete_value
        )
        self.assertEqual(
            m.read(16, 32).concrete_value,
            j.concrete_value
        )