import random
import cocotb
from cocotb.clock import Clock
from cocotb.runner import get_runner
from cocotb.triggers import RisingEdge

import copy

from dilithium import *

TEST_CASES = 10000

async def barrett_reduce_inputs(dut, inputs):
    for i in inputs:
        dut.X.value = i
        dut.vld_in.value = 1

        await RisingEdge(dut.clk)

    dut.X.value = 0
    dut.vld_in.value = 0

@cocotb.test()
async def test_barrett_reduce(dut):
    clk = Clock(dut.clk, 1, units='us')
    cocotb.start_soon(clk.start())

    dut.rst.value = 1
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)
    dut.rst.value = 0

    dut.mode.value = 1

    inputs = random.sample(range(0, Q * Q), TEST_CASES)

    cocotb.start_soon(barrett_reduce_inputs(dut, copy.copy(inputs)))

    await RisingEdge(dut.clk)

    while dut.vld_out.value != 1:
        await RisingEdge(dut.clk)

    for i in inputs:
        assert dut.Z.value.integer == barrett_reduce(i)

        await RisingEdge(dut.clk)

def run_tests():
    r = get_runner('ghdl')
    vhdl_sources = ['params_pkg.vhd', 'reduce_pkg.vhd', 'barrett_reduce.vhd']
    r.build(vhdl_sources=vhdl_sources, hdl_toplevel='barrett_reduce', always=True, build_args=['--std=08', '-frelaxed', '-fsynopsys'])
    r.test(hdl_toplevel='barrett_reduce', test_module='barrett_reduce_tb', test_args=['--std=08', '-frelaxed', '-fsynopsys'])

if __name__ == "__main__":
    run_tests()