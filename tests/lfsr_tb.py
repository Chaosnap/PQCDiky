import cocotb
from cocotb.clock import Clock
from cocotb.runner import get_runner
from cocotb.triggers import RisingEdge

import os

TEST_CASES = 1

@cocotb.test()
async def test_lfsr(dut):
    clk = Clock(dut.clk, 1, units='us')
    cocotb.start_soon(clk.start())

    dut.rst.value = 1
    dut.seed1.value = int.from_bytes(os.urandom(4), 'little')& 0x7fffffff
    dut.seed2.value = int.from_bytes(os.urandom(4), 'little')
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)
    dut.rst.value = 0

    for _ in range(10000):
        await RisingEdge(dut.clk)
        print(dut.random.value, end='')
    print()


def run_tests():
    r = get_runner('ghdl')
    r.build(vhdl_sources=['util_comps/lfsr.vhd'], toplevel='lfsr', always=True, build_args=['--std=08', '-frelaxed', '-fsynopsys'])
    r.test(hdl_toplevel='lfsr', test_module='lfsr_tb', test_args=['--std=08', '-frelaxed', '-fsynopsys'], plusargs=['--vcd=test.vcd'])

if __name__ == "__main__":
    run_tests()