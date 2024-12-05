import random
import cocotb
from cocotb.clock import Clock
from cocotb.runner import get_runner
from cocotb.triggers import RisingEdge

from dilithium import *

TEST_CASES = 10

async def validity_check_inputs(dut, inputs, mode, sec_level):
    dut.mode.value = mode

    k, l = k_l(sec_level)

    repeats = l if mode & 3 == 0 else k

    for i in inputs:
        for _ in range(repeats):
            for j in range(0, 256, 4):
                dut.coeffs.value = i[j] + (i[j + 1] << 24) + (i[j + 2] << 48) + (i[j + 3] << 72)
                dut.coeffs_vld.value = 1

                await RisingEdge(dut.clk)

                dut.coeffs_vld.value = 0

                if j != 252:
                    for _ in range(random.randint(1, 5)):
                        await RisingEdge(dut.clk)

    dut.mode.value = 0
    dut.coeffs.value = 0
    dut.coeffs_vld.value = 0

async def test_component(dut, mode, sec_level, inputs, outputs):
    clk = Clock(dut.clk, 1, units='us')
    cocotb.start_soon(clk.start())

    dut.rst.value = 1
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)
    dut.rst.value = 0

    cocotb.start_soon(validity_check_inputs(dut, inputs, mode, sec_level))

    await RisingEdge(dut.clk)

    for o in outputs:
        while dut.valid_vld.value != 1:
            await RisingEdge(dut.clk)

        print(dut.valid.value, o)
        assert dut.valid.value == (1 if o else 0)

        await RisingEdge(dut.clk)

@cocotb.test()
async def test_validity_check_z(dut):
    for sec_level, bound in [(2, 1 << 17), (3, 1 << 19), (5, 1 << 19)]:
        inputs = [[random.randint(-int(1.001 * bound), int(1.001 * bound)) for _ in range(256)] for _ in range(TEST_CASES)]
        outputs = [validity_check_z(i, sec_level) for i in inputs]

        inputs = [[x % Q for x in i] for i in inputs]

        mode = 0 if sec_level == 2 else 4 if sec_level == 3 else 8

        await test_component(dut, mode, sec_level, inputs, outputs)

@cocotb.test()
async def test_validity_check_r0(dut):
    for sec_level, bound in [(2, (Q - 1) // 88), (3, (Q - 1) // 32), (5, (Q - 1) // 32)]:
        inputs = [[random.randint(0, int(1.001 * bound)) for _ in range(256)] for _ in range(TEST_CASES)]
        outputs = [validity_check_r0(i, sec_level) for i in inputs]

        mode = 1 if sec_level == 2 else 5 if sec_level == 3 else 9

        await test_component(dut, mode, sec_level, inputs, outputs)

@cocotb.test()
async def test_validity_check_ct0(dut):
    for sec_level, bound in [(2, (Q - 1) // 88), (3, (Q - 1) // 32), (5, (Q - 1) // 32)]:
        inputs = [[random.randint(-int(1.001 * bound), int(1.001 * bound)) for _ in range(256)] for _ in range(TEST_CASES)]
        outputs = [validity_check_ct0(i, sec_level) for i in inputs]

        inputs = [[x % Q for x in i] for i in inputs]

        mode = 2 if sec_level == 2 else 6 if sec_level == 3 else 10

        await test_component(dut, mode, sec_level, inputs, outputs)

def run_tests():
    r = get_runner('ghdl')
    vhdl_sources = ['params_pkg.vhd', 'reduce_pkg.vhd', 'validity_check.vhd']
    r.build(vhdl_sources=vhdl_sources, hdl_toplevel='validity_check', always=True, build_args=['--std=08', '-frelaxed', '-fsynopsys'])
    r.test(hdl_toplevel='validity_check', test_module='validity_check_tb', test_args=['--std=08', '-frelaxed', '-fsynopsys'])
    # r.test(hdl_toplevel='validity_check', test_module='validity_check_tb', test_args=['--std=08', '-frelaxed', '-fsynopsys'], plusargs=['--vcd=test.vcd'])

if __name__ == "__main__":
    run_tests()