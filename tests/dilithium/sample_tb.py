import random
import cocotb
from cocotb.clock import Clock
from cocotb.runner import get_runner
from cocotb.triggers import RisingEdge
from os import urandom

from dilithium import *

TEST_CASES = 100

async def sample_inputs(dut, inputs, mode):
    dut.s_axis_tuser.value = mode

    for x in inputs:
        while len(x) % 8 != 0:
            x += b'\x00'

        for i in range(0, len(x), 8):
            dut.s_axis_tdata.value = int.from_bytes(x[i: i + 8], 'little')
            dut.s_axis_tvalid.value = 1

            await RisingEdge(dut.clk)

            while dut.s_axis_tready.value != 1:
                await RisingEdge(dut.clk)

            dut.s_axis_tvalid.value = 0

            if i != len(x) - 8:
                for _ in range(random.randint(0, 5)):
                    await RisingEdge(dut.clk)

        while (dut.m_axis_tvalid.value and dut.m_axis_tlast.value and dut.m_axis_tready.value) == 0:
            dut.s_axis_tdata.value = 0
            dut.s_axis_tvalid.value = 1
            await RisingEdge(dut.clk)

        dut.s_axis_tvalid.value = 0

        for _ in range(random.randint(1, 5)):
            await RisingEdge(dut.clk)

    dut.s_axis_tdata.value = 0
    dut.s_axis_tvalid.value = 0

async def test_sample(dut, mode, inputs, outputs):
    clk = Clock(dut.clk, 1, units='us')
    cocotb.start_soon(clk.start())

    dut.rst.value = 1
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)
    dut.rst.value = 0

    cocotb.start_soon(sample_inputs(dut, inputs, mode))

    dut.m_axis_tready.value = 1

    await RisingEdge(dut.clk)

    for o in outputs:
        for i in range(0, 256, 4):
            while dut.m_axis_tvalid.value != 1:
                await RisingEdge(dut.clk)

            assert dut.m_axis_tdata.value.buff == bytes.fromhex(f'{o[i + 3]:06x}{o[i + 2]:06x}{o[i + 1]:06x}{o[i]:06x}')

            dut.m_axis_tready.value = 0

            for _ in range(random.randint(0, 5)):
                await RisingEdge(dut.clk)

            dut.m_axis_tready.value = 1

            await RisingEdge(dut.clk)

@cocotb.test()
async def test_sample_ntt(dut):
    inputs = []
    outputs = []

    for _ in range(TEST_CASES):
        i = b''
        o = []
        while len(o) < 256:
            x = urandom(6)
            sample_ntt(x, o)

            i += x

        inputs.append(i)
        outputs.append(o)

    await test_sample(dut, 4, inputs, outputs)

@cocotb.test()
async def test_sample_bounded2(dut):
    inputs = []
    outputs = []

    for _ in range(TEST_CASES):
        i = b''
        o = []
        while len(o) < 256:
            x = urandom(1)
            sample_bounded2(x, o)

            i += x

        inputs.append(i)
        outputs.append(o)

    await test_sample(dut, 5, inputs, outputs)

@cocotb.test()
async def test_sample_bounded4(dut):
    inputs = []
    outputs = []

    for _ in range(TEST_CASES):
        i = b''
        o = []
        while len(o) < 256:
            x = urandom(1)
            sample_bounded4(x, o)

            i += x

        inputs.append(i)
        outputs.append(o)

    await test_sample(dut, 6, inputs, outputs)

def run_tests():
    r = get_runner('ghdl')
    vhdl_sources = ['params_pkg.vhd', 'sample_pkg.vhd', 'sample.vhd']
    r.build(vhdl_sources=vhdl_sources, hdl_toplevel='sample', always=True, build_args=['--std=08', '-frelaxed', '-fsynopsys'])
    r.test(hdl_toplevel='sample', test_module='sample_tb', test_args=['--std=08', '-frelaxed', '-fsynopsys'])

if __name__ == "__main__":
    run_tests()