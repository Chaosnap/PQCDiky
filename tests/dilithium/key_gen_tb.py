import random
import cocotb
from cocotb.clock import Clock, Timer
from cocotb.runner import get_runner
from cocotb.triggers import RisingEdge
from cocotb.utils import get_sim_time
from os import urandom
import copy

from dilithium import *
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

async def data_checks(dut, seed, sk, sec_level):
    await check_data(dut, dut.data_input_loaded, seed)

    expanded_seed = expand_seed(seed, sec_level)
    await check_data(dut, dut.rho_prime_vld, expanded_seed[:32] + b'\x00' * 96 + expanded_seed[32:])

    print('data finished')

async def bram0_checks(dut, seed, sk, sec_level):
    k, l = k_l(sec_level)
    poly_offset = 0

    data = expand_seed(seed, sec_level)
    t0, s1, s2 = unpack_sk(sk, sec_level)
    a = expand_a(data[:32], sec_level)

    for i in range(l):
        await check_memory(dut, dut.bram0, s1[i].to_numpy(), vld_sig=dut.bram0_polys_vld, poly_offset=poly_offset)
        poly_offset = (poly_offset + 1) % 8

        for j in range(k):
            await check_memory(dut, dut.bram0, a[j][i].to_numpy(), vld_sig=dut.bram0_polys_vld, poly_offset=poly_offset)
            poly_offset = (poly_offset + 1) % 8

    for i in range(k):
        await check_memory(dut, dut.bram0, s2[i].to_numpy(), vld_sig=dut.bram0_polys_vld, poly_offset=poly_offset)
        poly_offset = (poly_offset + 1) % 8

    print('bram0 finished')

async def bram1_checks(dut, seed, sk, sec_level):
    k, l = k_l(sec_level)
    t0, s1, s2 = unpack_sk(sk, sec_level)
    data = expand_seed(seed, sec_level)
    a = expand_a(data[:32], sec_level)

    async def wait_for_vld_addr(offset):
        while not (dut.bram1.wea.value == 1 and dut.poly_mul.vld == 1 and dut.bram1.addra.value == (offset + 1) * 64 - 1):
            await RisingEdge(dut.clk)


    t_ntt = [np.zeros((256, ), dtype=np.int32) for _ in range(k)]
    s1_ntt = []

    for i in range(l):
        await wait_for_vld_addr(l + k + i)
        s1_ntt.append(ntt(s1[i].to_numpy()))
        await check_memory(dut, dut.bram1, s1_ntt[-1], poly_offset=l + k + i)

        for j in range(k):
            t_ntt[j] = barrett_reduce(t_ntt[j] + s1_ntt[-1] * a[j][i].to_numpy())

            await wait_for_vld_addr(2 * (l + k) + j)
            await check_memory(dut, dut.bram1, t_ntt[j], poly_offset=2 * (l + k) + j)

    t = compute_w_t(a, s1, sec_level)

    for i in range(k):
        await wait_for_vld_addr(2 * (l + k) + i)
        await check_memory(dut, dut.bram1, t[i].to_numpy(), poly_offset=2 * (l + k) + i)

    print('bram1 finished')


async def test_dilithium_key_gen(dut, sec_level):
    clk = Clock(dut.clk, 100, units='ns')
    cocotb.start_soon(clk.start())

    dut.rst.value = 1
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)
    dut.rst.value = 0

    await RisingEdge(dut.clk)

    for _ in range(TEST_CASES):
        mode = 0b00001000000 if sec_level == 2 else 0b01001000000 if sec_level == 3 else 0b10001000000

        pk, sk, seed = key_pair(sec_level)

        cocotb.start_soon(sample_inputs(dut, seed, mode))

        await RisingEdge(dut.clk)

        tasks = [
            cocotb.start_soon(bram0_checks(dut, seed, sk, sec_level)),
            cocotb.start_soon(bram1_checks(dut, seed, sk, sec_level)),
            cocotb.start_soon(data_checks(dut, seed, sk, sec_level))
        ]

        dut.m_axis_tready.value = 1
        await RisingEdge(dut.clk)

        for i in range(0, len(pk), 8):
            while dut.m_axis_tvalid.value != 1:
                await RisingEdge(dut.clk)

            # print(dut.m_axis_tdata.value.buff.hex())
            # print(pk[i:i+8][::-1].hex())
            assert dut.m_axis_tdata.value.buff == pk[i:i+8][::-1]

            dut.m_axis_tready.value = 0

            for _ in range(random.randint(0, 5)):
                await RisingEdge(dut.clk)

            dut.m_axis_tready.value = 1

            await RisingEdge(dut.clk)

        for i in range(0, len(sk), 8):
            while dut.m_axis_tvalid.value != 1:
                await RisingEdge(dut.clk)

            # print(dut.m_axis_tdata.value.buff.hex())
            # print(sk[i:i+8][::-1].hex())
            # print(i // 8)
            assert dut.m_axis_tdata.value.buff == sk[i:i+8][::-1]

            dut.m_axis_tready.value = 0

            for _ in range(random.randint(0, 5)):
                await RisingEdge(dut.clk)

            dut.m_axis_tready.value = 1

            await RisingEdge(dut.clk)



@cocotb.test()
async def test_dilithium_key_gen2(dut):
    await test_dilithium_key_gen(dut, 2)

@cocotb.test()
async def test_dilithium_key_gen3(dut):
    await test_dilithium_key_gen(dut, 3)

@cocotb.test()
async def test_dilithium_key_gen5(dut):
    await test_dilithium_key_gen(dut, 5)




def run_tests():
    r = get_runner('ghdl')
    vhdl_sources = ['params_pkg.vhd', 'sample_pkg.vhd', 'reduce_pkg.vhd', 'util_comps/math_pkg.vhd', 'util_comps/small_fifo.vhd', 'util_comps/reg_ready.vhd', 'barrett_reduce.vhd', 'butterfly.vhd', 'poly_mul.vhd', 'poly_mul_state_machine.vhd', 'util_comps/bram.vhd', 'bram1_state_machine.vhd', 'sample.vhd', 'sample_in_ball.vhd', 'keccak.vhd', 'keccak_state_machine.vhd', 'encode.vhd', 'decode.vhd', 'compress.vhd', 'validity_check.vhd', 'make_hint.vhd', 'use_hint.vhd', 'out_state_machine.vhd', 'in_state_machine.vhd', 'top.vhd']
    r.build(vhdl_sources=vhdl_sources, hdl_toplevel='top', always=True, build_args=['--std=08', '-frelaxed', '-fsynopsys'])
    r.test(hdl_toplevel='top', test_module='key_gen_tb', test_args=['--std=08', '-frelaxed', '-fsynopsys'], parameters={'SIMULATION': True})
    # r.test(hdl_toplevel='top', test_module='key_gen_tb', test_args=['--std=08', '-frelaxed', '-fsynopsys'], parameters={'SIMULATION': True}, plusargs=['--vcd=test.vcd'])

if __name__ == "__main__":
    run_tests()
