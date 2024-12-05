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

async def data_checks(dut, sk, c, m, K, r, k):
    await check_data(dut, dut.c_vld, sk[-96:-64] + b'\x00' * 32 + sk[-64:])

    await check_data(dut, dut.rho_prime_vld, sk[-96:-64] + b'\x00' * 32 + sk[-64:-32] + K + r + b'\x00' * 64 + j(sk[-32:], c))

    print('data finished')

async def bram0_checks(dut, sk, c, m, K, r, k):
    poly_offset = 0
    u, v = unpack_c(c, k)

    for i in range(k):
        await check_memory(dut, dut.bram0, u[i].to_numpy(), vld_sig=dut.bram0_polys_vld, poly_offset=poly_offset)
        poly_offset = (poly_offset + 1) % 16

    await check_memory(dut, dut.bram0, v.to_numpy(), vld_sig=dut.bram0_polys_vld, poly_offset=poly_offset)
    poly_offset = (poly_offset + 1) % 16


    a = expand_a(sk[-96:-64], k)

    for i in range(k):
        await check_memory(dut, dut.bram0, sample_cbd(r, i, k).to_numpy(), vld_sig=dut.bram0_polys_vld, poly_offset=poly_offset)
        poly_offset = (poly_offset + 1) % 16

    for i in range(k):
        for j in range(k):
            await check_memory(dut, dut.bram0, a[j][i].to_numpy(), vld_sig=dut.bram0_polys_vld, poly_offset=poly_offset)
            poly_offset = (poly_offset + 1) % 16

    for i in range(k):
        await check_memory(dut, dut.bram0, sample_cbd(r, k + i, 3).to_numpy(), vld_sig=dut.bram0_polys_vld, poly_offset=poly_offset)
        poly_offset = (poly_offset + 1) % 16

    await check_memory(dut, dut.bram0, sample_cbd(r, 2 * k, 3).to_numpy(), vld_sig=dut.bram0_polys_vld, poly_offset=poly_offset)
    poly_offset = (poly_offset + 1) % 16

    print('bram0 finished')

async def bram1_checks(dut, sk, c, m, K, r, k):
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

        await wait_for_vld_addr(2 * k)
        await check_memory(dut, dut.bram1, c, poly_offset=5 * k)
        await check_memory(dut, dut.bram1, d, poly_offset=2 * k)

        w = (w + z) % Q

        await wait_for_vld_addr(2 * k)
        await check_memory(dut, dut.bram1, w, poly_offset=2 * k)

    await wait_for_vld_addr(2 * k)
    await check_memory(dut, dut.bram1, intt(w), poly_offset=2 * k)

    t = unpack_pk(sk[384 * k:], k)
    a = expand_a(sk[-96:-64], k)

    while dut.rho_prime_vld.value != 1:
        await RisingEdge(dut.clk)

    for i in range(0, len(m), 8):
        dut.bram1.debug_addr.value = (4 * k * 256 + i) // 8
        await Timer(10, units='ns')
        assert compress(dut.bram1.debug_data.value.integer & 0xfff, 1) == m[i // 8] & 0x1
        assert compress((dut.bram1.debug_data.value.integer >> 12) & 0xfff, 1) == (m[i // 8] >> 1) & 0x1
        assert compress((dut.bram1.debug_data.value.integer >> 24) & 0xfff, 1) == (m[i // 8] >> 2) & 0x1
        assert compress((dut.bram1.debug_data.value.integer >> 36) & 0xfff, 1) == (m[i // 8] >> 3) & 0x1
        assert compress((dut.bram1.debug_data.value.integer >> 48) & 0xfff, 1) == (m[i // 8] >> 4) & 0x1
        assert compress((dut.bram1.debug_data.value.integer >> 60) & 0xfff, 1) == (m[i // 8] >> 5) & 0x1
        assert compress((dut.bram1.debug_data.value.integer >> 72) & 0xfff, 1) == (m[i // 8] >> 6) & 0x1
        assert compress((dut.bram1.debug_data.value.integer >> 84) & 0xfff, 1) == (m[i // 8] >> 7) & 0x1

    r_ntt = []
    for i in range(k):
        r_ntt.append(ntt(sample_cbd(r, i, k).to_numpy()))
        await wait_for_vld_addr(2 * k + 1 + i)
        await check_memory(dut, dut.bram1, r_ntt[-1], poly_offset=2 * k + 1 + i)

    for i in range(k):
        await check_memory(dut, dut.bram1, t[i].to_numpy(), poly_offset=k + i)

    u = np.zeros_like(r_ntt)

    for i in range(k):
        for j in range(k):
            c, d = butterfly_mul0_poly(r_ntt[j], a[j][i].to_numpy())
            z = butterfly_mul1_poly(c, d)

            await wait_for_vld_addr(5 * k + 1 + i)
            await check_memory(dut, dut.bram1, c, poly_offset=4 * k + 1 + i)
            await check_memory(dut, dut.bram1, d, poly_offset=5 * k + 1 + i)

            u[i] = (u[i] + z) % Q
            await wait_for_vld_addr(3 * k + 1 + i)
            await check_memory(dut, dut.bram1, u[i], poly_offset=3 * k + 1 + i)

    v = np.zeros_like(r_ntt[0])

    for i in range(k):
        c, d = butterfly_mul0_poly(r_ntt[i], t[i].to_numpy())
        z = butterfly_mul1_poly(c, d)

        await wait_for_vld_addr(5 * k + 1)
        await check_memory(dut, dut.bram1, c, poly_offset=2 * k + 1)
        await check_memory(dut, dut.bram1, d, poly_offset=5 * k + 1)

        v = (v + z) % Q

        await wait_for_vld_addr(2 * k + 1)
        await check_memory(dut, dut.bram1, v, poly_offset=2 * k + 1)

    for i in range(k):
        await wait_for_vld_addr(3 * k + 1 + i)
        await check_memory(dut, dut.bram1, intt(u[i]), poly_offset=3 * k + 1 + i)

    await wait_for_vld_addr(2 * k + 1)
    await check_memory(dut, dut.bram1, intt(v), poly_offset=2 * k + 1)

    for i in range(0, len(m), 8):
        dut.bram1.debug_addr.value = (4 * k * 256 + i) // 8
        await Timer(10, units='ns')
        assert compress(dut.bram1.debug_data.value.integer & 0xfff, 1) == m[i // 8] & 0x1
        assert compress((dut.bram1.debug_data.value.integer >> 12) & 0xfff, 1) == (m[i // 8] >> 1) & 0x1
        assert compress((dut.bram1.debug_data.value.integer >> 24) & 0xfff, 1) == (m[i // 8] >> 2) & 0x1
        assert compress((dut.bram1.debug_data.value.integer >> 36) & 0xfff, 1) == (m[i // 8] >> 3) & 0x1
        assert compress((dut.bram1.debug_data.value.integer >> 48) & 0xfff, 1) == (m[i // 8] >> 4) & 0x1
        assert compress((dut.bram1.debug_data.value.integer >> 60) & 0xfff, 1) == (m[i // 8] >> 5) & 0x1
        assert compress((dut.bram1.debug_data.value.integer >> 72) & 0xfff, 1) == (m[i // 8] >> 6) & 0x1
        assert compress((dut.bram1.debug_data.value.integer >> 84) & 0xfff, 1) == (m[i // 8] >> 7) & 0x1

    print('bram1 finished')


async def test_kyber_kem_dec(dut, k):
    clk = Clock(dut.clk, 1, units='us')
    cocotb.start_soon(clk.start())

    dut.rst.value = 1
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)
    dut.rst.value = 0

    await RisingEdge(dut.clk)

    for _ in range(TEST_CASES):
        mode = 0b00000100000 if k == 2 else 0b01000100000 if k == 3 else 0b10000100000

        coins = urandom(64)
        pk, sk = kem_key_pair(coins, k)
        m = urandom(32)
        K, r = k_r(m, pk)
        c = pke_enc(pk, m, r, k)

        valid = True
        # if random.random() < 0.5:
        #     valid = False

        #     if random.random() < 0.5:
        #         print('changing c')
        #         i = random.randint(0, len(c) - 1)
        #         c = c[:i] + urandom(1) + c[i + 1:]
        #     else:
        #         print('changing sk')
        #         i = random.randint(0, len(sk) - 1)
        #         sk = sk[:i] + urandom(1) + sk[i + 1:]

        cocotb.start_soon(sample_inputs(dut, sk + c, mode))

        await RisingEdge(dut.clk)

        tasks = [
            cocotb.start_soon(bram0_checks(dut, sk, c, m, K, r, k)),
            cocotb.start_soon(bram1_checks(dut, sk, c, m, K, r, k)),
            cocotb.start_soon(data_checks(dut, sk, c, m, K, r, k))
        ]

        if not valid:
            K = j(sk[-32:], c)

        for task in tasks:
            await task.join()

        dut.m_axis_tready.value = 1
        await RisingEdge(dut.clk)

        for i in range(0, len(K), 8):
            while dut.m_axis_tvalid.value != 1:
                await RisingEdge(dut.clk)

            # print(dut.m_axis_tdata.value.buff.hex())
            # print(K[i:i+8][::-1].hex())
            assert dut.m_axis_tdata.value.buff == K[i:i+8][::-1]

            dut.m_axis_tready.value = 0

            for _ in range(random.randint(0, 50)):
                await RisingEdge(dut.clk)

            dut.m_axis_tready.value = 1

            await RisingEdge(dut.clk)



@cocotb.test()
async def test_kyber_kem_dec2(dut):
    await test_kyber_kem_dec(dut, 2)

@cocotb.test()
async def test_kyber_kem_dec3(dut):
    await test_kyber_kem_dec(dut, 3)

@cocotb.test()
async def test_kyber_kem_dec4(dut):
    await test_kyber_kem_dec(dut, 4)




def run_tests():
    r = get_runner('ghdl')
    vhdl_sources = ['params_pkg.vhd', 'sample_pkg.vhd', 'reduce_pkg.vhd', 'util_comps/math_pkg.vhd', 'util_comps/small_fifo.vhd', 'util_comps/reg_ready.vhd', 'barrett_reduce.vhd', 'butterfly.vhd', 'poly_mul.vhd', 'poly_mul_state_machine.vhd', 'util_comps/bram.vhd', 'bram1_state_machine.vhd', 'sample.vhd', 'sample_in_ball.vhd', 'keccak.vhd', 'keccak_state_machine.vhd', 'encode.vhd', 'decode.vhd', 'compress.vhd', 'validity_check.vhd', 'make_hint.vhd', 'use_hint.vhd', 'out_state_machine.vhd', 'in_state_machine.vhd', 'top.vhd']
    r.build(vhdl_sources=vhdl_sources, hdl_toplevel='top', always=True, build_args=['--std=08', '-frelaxed', '-fsynopsys'])
    r.test(hdl_toplevel='top', test_module='kem_dec_tb', test_args=['--std=08', '-frelaxed', '-fsynopsys'], parameters={'SIMULATION': True})
    # r.test(hdl_toplevel='top', test_module='kem_dec_tb', test_args=['--std=08', '-frelaxed', '-fsynopsys'], parameters={'SIMULATION': True}, plusargs=['--vcd=test.vcd'])

if __name__ == "__main__":
    run_tests()
