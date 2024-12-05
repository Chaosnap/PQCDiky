import random
import cocotb
from cocotb.clock import Clock, Timer
from cocotb.runner import get_runner
from cocotb.triggers import RisingEdge
from cocotb.utils import get_sim_time
from os import urandom
import copy

from kyber import *
from utils import *

TEST_CASES = 10

async def sample_inputs(dut, inputs, mode):
    dut.s_axis_tuser.value = mode

    for i in range(0, len(inputs), 8):
        dut.s_axis_tdata.value = int.from_bytes(inputs[i: i + 8], 'little')
        dut.s_axis_tlast.value = 1 if i == len(inputs) - 8 else 0
        dut.s_axis_tvalid.value = 1

        await RisingEdge(dut.clk)

        while dut.s_axis_tready.value != 1:
            await RisingEdge(dut.clk)

        dut.s_axis_tvalid.value = 0

        for _ in range(random.randint(0, 5)):
            await RisingEdge(dut.clk)

    dut.s_axis_tdata.value = 0
    dut.s_axis_tuser.value = 0
    dut.s_axis_tlast.value = 0
    dut.s_axis_tvalid.value = 0

async def bram0_checks(dut, sk , c, k):
    poly_offset = 0
    u, v = unpack_c(c, k)

    for i in range(k):
        await check_memory(dut, dut.bram0, u[i].to_numpy(), vld_sig=dut.bram0_polys_vld, poly_offset=poly_offset)
        poly_offset = (poly_offset + 1) % 16

    await check_memory(dut, dut.bram0, v.to_numpy(), vld_sig=dut.bram0_polys_vld, poly_offset=poly_offset)
    poly_offset = (poly_offset + 1) % 16

    print('bram0 finished')

async def bram1_checks(dut, sk , c, k):
    s = unpack_sk(sk, k)
    u, v = unpack_c(c, k)

    async def wait_for_vld_addr(offset):
        while not (dut.bram1.wea.value == 1 and dut.poly_mul.vld == 1 and dut.bram1.addra.value == (offset + 1) * 64 - 33):
            await RisingEdge(dut.clk)

    u_ntt = []
    for i in range(k):
        u_ntt.append(ntt(u[i].to_numpy()))
        await wait_for_vld_addr(2 * k + i)
        await check_memory(dut, dut.bram1, u_ntt[-1], poly_offset=2 * k + i)

    for i in range(k):
        await check_memory(dut, dut.bram1, s[i].to_numpy(), poly_offset=i)

    w = np.zeros_like(u_ntt[0])

    for i in range(k):
        c, d = butterfly_mul0_poly(u_ntt[i], s[i].to_numpy())
        z = butterfly_mul1_poly(c, d)

        await wait_for_vld_addr(5 * k)
        await check_memory(dut, dut.bram1, c, poly_offset=5 * k)
        await check_memory(dut, dut.bram1, d, poly_offset=2 * k)

        w = (w + z) % Q

        await wait_for_vld_addr(2 * k)
        await check_memory(dut, dut.bram1, w, poly_offset=2 * k)

    await wait_for_vld_addr(2 * k)
    await check_memory(dut, dut.bram1, intt(w), poly_offset=2 * k)

    print('bram1 finished')


async def test_kyber_pke_dec(dut, k):
    clk = Clock(dut.clk, 1, units='us')
    cocotb.start_soon(clk.start())

    dut.rst.value = 1
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)
    dut.rst.value = 0

    await RisingEdge(dut.clk)

    for _ in range(TEST_CASES):
        mode = 0b00000000100 if k == 2 else 0b01000000100 if k == 3 else 0b10000000100

        coins = urandom(32)
        pk, sk = pke_key_pair(coins, k)
        m = urandom(32)
        r = urandom(32)
        c = pke_enc(pk, m, r, k)

        cocotb.start_soon(sample_inputs(dut, sk + c, mode))

        await RisingEdge(dut.clk)

        tasks = [
            cocotb.start_soon(bram0_checks(dut, sk, c, k)),
            cocotb.start_soon(bram1_checks(dut, sk, c, k))
        ]

        dut.m_axis_tready.value = 1
        await RisingEdge(dut.clk)

        for i in range(0, len(m), 8):
            while dut.m_axis_tvalid.value != 1:
                await RisingEdge(dut.clk)

            # print(dut.m_axis_tdata.value.buff.hex())
            # print(pk[i:i+8][::-1].hex())
            assert dut.m_axis_tdata.value.buff == m[i:i+8][::-1]

            dut.m_axis_tready.value = 0

            for _ in range(random.randint(0, 50)):
                await RisingEdge(dut.clk)

            dut.m_axis_tready.value = 1

            await RisingEdge(dut.clk)



@cocotb.test()
async def test_kyber_pke_dec2(dut):
    await test_kyber_pke_dec(dut, 2)

@cocotb.test()
async def test_kyber_pke_dec3(dut):
    await test_kyber_pke_dec(dut, 3)

@cocotb.test()
async def test_kyber_pke_dec4(dut):
    await test_kyber_pke_dec(dut, 4)




def run_tests():
    r = get_runner('ghdl')
    vhdl_sources = ['params_pkg.vhd', 'sample_pkg.vhd', 'reduce_pkg.vhd', 'util_comps/math_pkg.vhd', 'util_comps/small_fifo.vhd', 'util_comps/reg_ready.vhd', 'barrett_reduce.vhd', 'butterfly.vhd', 'poly_mul.vhd', 'poly_mul_state_machine.vhd', 'util_comps/bram.vhd', 'bram1_state_machine.vhd', 'sample.vhd', 'sample_in_ball.vhd', 'keccak.vhd', 'keccak_state_machine.vhd', 'encode.vhd', 'decode.vhd', 'compress.vhd', 'validity_check.vhd', 'make_hint.vhd', 'use_hint.vhd', 'out_state_machine.vhd', 'in_state_machine.vhd', 'top.vhd']
    r.build(vhdl_sources=vhdl_sources, hdl_toplevel='top', always=True, build_args=['--std=08', '-frelaxed', '-fsynopsys'])
    r.test(hdl_toplevel='top', test_module='pke_dec_tb', test_args=['--std=08', '-frelaxed', '-fsynopsys'], parameters={'SIMULATION': True})
    # r.test(hdl_toplevel='top', test_module='pke_dec_tb', test_args=['--std=08', '-frelaxed', '-fsynopsys'], parameters={'SIMULATION': True}, plusargs=['--vcd=test.vcd'])

if __name__ == "__main__":
    run_tests()
