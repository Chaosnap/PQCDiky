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

    # add padding to message
    inputs += b'\x1f'

    # make sure it is aligned to 8B
    while len(inputs) % 8 != 0:
        inputs += b'\x00'

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

async def data_checks(dut, sk, msg, rnd, sec_level):
    await check_data(dut, dut.data_input_loaded, sk[:128])
    await check_data(dut, dut.rho_prime_vld, sk[:64] + mu(sk, msg) + rho_prime(sk, msg, rnd))

    k, l = k_l(sec_level)

    kappa = 0

    while True:
        a = expand_a(sk[:32], sec_level)
        y = expand_mask(rho_prime(sk, msg, rnd), kappa, sec_level)
        kappa += 1

        w = compute_w_t(a, copy.deepcopy(y), sec_level)

        ch, w0 = compute_c(mu(sk, msg), w, sec_level)


        await check_data(dut, dut.c_vld, sk[:64] + mu(sk, msg) + rho_prime(sk, msg, rnd) + ch)

        t0, s1, s2 = unpack_sk(sk, sec_level)
        z = compute_z(ch, y, s1, sec_level)
        r0 = compute_r0(ch, w0, s2, sec_level)
        ct0 = compute_ct0(ch, t0, sec_level)

        valid = True
        for i in range(l):
            valid = valid and validity_check_z(z[i].to_numpy(), sec_level)
        for i in range(k):
            valid = valid and validity_check_r0(r0[i].to_numpy(), sec_level)
            valid = valid and validity_check_ct0(ct0[i].to_numpy(), sec_level)

        if not valid:
            while dut.c_vld.value == 1:
                await RisingEdge(dut.clk)
            continue

        _, valid = make_hint(r0, w, sec_level, ct0)

        if not valid:
            while dut.c_vld.value == 1:
                await RisingEdge(dut.clk)
            continue

        break

    print('data finished')

async def bram0_checks(dut, sk, msg, rnd, sec_level):
    poly_offset = 0

    k, l = k_l(sec_level)
    t0, s1, s2 = unpack_sk(sk, sec_level)

    for i in range(l):
        await check_memory(dut, dut.bram0, s1[i].to_numpy(), vld_sig=dut.bram0_polys_vld, poly_offset=poly_offset)
        poly_offset = (poly_offset + 1) % 8

    for i in range(k):
        await check_memory(dut, dut.bram0, s2[i].to_numpy(), vld_sig=dut.bram0_polys_vld, poly_offset=poly_offset)
        poly_offset = (poly_offset + 1) % 8

    for i in range(k):
        await check_memory(dut, dut.bram0, t0[i].to_numpy(), vld_sig=dut.bram0_polys_vld, poly_offset=poly_offset)
        poly_offset = (poly_offset + 1) % 8

    kappa = 0

    while True:
        a = expand_a(sk[:32], sec_level)
        y = expand_mask(rho_prime(sk, msg, rnd), kappa, sec_level)
        kappa += 1

        for i in range(l):
            await check_memory(dut, dut.bram0, y[i].to_numpy(), vld_sig=dut.bram0_polys_vld, poly_offset=poly_offset)
            poly_offset = (poly_offset + 1) % 8

            for j in range(k):
                await check_memory(dut, dut.bram0, a[j][i].to_numpy(), vld_sig=dut.bram0_polys_vld, poly_offset=poly_offset)
                poly_offset = (poly_offset + 1) % 8

        w = compute_w_t(a, copy.deepcopy(y), sec_level)
        ch, w0 = compute_c(mu(sk, msg), w, sec_level)
        _, c = sample_in_ball(ch, sec_level)

        await check_memory(dut, dut.bram0, c, vld_sig=dut.bram0_polys_vld, poly_offset=poly_offset)
        poly_offset = (poly_offset + 1) % 8

        await check_memory(dut, dut.bram0, ntt(np.array(c)), vld_sig=dut.bram0_polys_vld, poly_offset=poly_offset)

        t0, s1, s2 = unpack_sk(sk, sec_level)
        z = compute_z(ch, y, s1, sec_level)
        r0 = compute_r0(ch, w0, s2, sec_level)
        ct0 = compute_ct0(ch, t0, sec_level)

        valid = True
        for i in range(l):
            valid = valid and validity_check_z(z[i].to_numpy(), sec_level)
        for i in range(k):
            valid = valid and validity_check_r0(r0[i].to_numpy(), sec_level)
            valid = valid and validity_check_ct0(ct0[i].to_numpy(), sec_level)


        if not valid:
            poly_offset = 0
            continue

        _, valid = make_hint(r0, w, sec_level, ct0)

        if not valid:
            poly_offset = 0
            continue

        break


    print('bram0 finished')

async def bram1_checks(dut, sk, msg, rnd, sec_level):
    k, l = k_l(sec_level)
    t0, s1, s2 = unpack_sk(sk, sec_level)

    async def wait_for_vld_addr(offset):
        while not (dut.bram1.wea.value == 1 and dut.poly_mul.vld == 1 and dut.bram1.addra.value == (offset + 1) * 64 - 1):
            await RisingEdge(dut.clk)

    s1_ntt = []
    s2_ntt = []
    t0_ntt = []

    for i in range(l):
        await wait_for_vld_addr(i)
        s1_ntt.append(ntt(s1[i].to_numpy()))
        await check_memory(dut, dut.bram1, s1_ntt[-1], poly_offset=i)

    for i in range(k):
        await wait_for_vld_addr(l + i)
        s2_ntt.append(ntt(s2[i].to_numpy()))
        await check_memory(dut, dut.bram1, s2_ntt[-1], poly_offset=l + i)

    for i in range(k):
        await wait_for_vld_addr(l + k + i)
        t0_ntt.append(ntt(t0[i].to_numpy()))
        await check_memory(dut, dut.bram1, t0_ntt[-1], poly_offset=l + k + i)

    kappa = 0

    while True:
        a = expand_a(sk[:32], sec_level)
        y = expand_mask(rho_prime(sk, msg, rnd), kappa, sec_level)
        kappa += 1

        w_ntt = [np.zeros((256, ), dtype=np.int32) for _ in range(k)]
        y_ntt = []

        for i in range(l):
            await wait_for_vld_addr(l + 2 * k + i)
            y_ntt.append(ntt(y[i].to_numpy()))
            await check_memory(dut, dut.bram1, y_ntt[-1], poly_offset=l + 2 * k + i)

            for j in range(k):
                w_ntt[j] = barrett_reduce(w_ntt[j] + y_ntt[-1] * a[j][i].to_numpy())

                await wait_for_vld_addr(2 * (l + k) + j)
                await check_memory(dut, dut.bram1, w_ntt[j], poly_offset=2 * (l + k) + j)


        w = compute_w_t(a, copy.deepcopy(y), sec_level)

        for i in range(k):
            await wait_for_vld_addr(3 * k + 2 * l + i)
            await check_memory(dut, dut.bram1, w[i].to_numpy(), poly_offset=3 * k + 2 * l + i)

        ch, w0 = compute_c(mu(sk, msg), copy.deepcopy(w), sec_level)
        _, c = sample_in_ball(ch, sec_level)

        t0, s1, s2 = unpack_sk(sk, sec_level)

        z = compute_z(ch, y, s1, sec_level)

        valid = True

        for i in range(l):
            ntt_c = ntt(np.array(c))
            tmp = np.array([barrett_reduce(ntt_c[j] * s1_ntt[i][j] + y_ntt[i][j]) for j in range(256)])

            await wait_for_vld_addr(l + 2 * k + i)
            await check_memory(dut, dut.bram1, tmp, poly_offset=l + 2 * k + i)

            await wait_for_vld_addr(l + 2 * k + i)
            await check_memory(dut, dut.bram1, z[i].to_numpy(), poly_offset=l + 2 * k + i)

            valid = valid and validity_check_z(z[i].to_numpy(), sec_level)

        print(f'validity_check_z: {valid}')

        if not valid:
            continue

        r0 = compute_r0(ch, w0, s2, sec_level)

        for i in range(k):
            ntt_c = ntt(np.array(c))
            tmp = np.array([barrett_reduce(w_ntt[i][j] - ntt_c[j] * s2_ntt[i][j]) for j in range(256)])

            await wait_for_vld_addr(2 * (l + k) + i)
            await check_memory(dut, dut.bram1, tmp, poly_offset=2 * (l + k) + i)

            tmp = intt(tmp)

            await wait_for_vld_addr(2 * (l + k) + i)
            await check_memory(dut, dut.bram1, tmp, poly_offset=2 * (l + k) + i)

            valid = valid and validity_check_r0(r0[i].to_numpy(), sec_level)

        print(f'validity_check_r0: {valid}')

        if not valid:
            continue

        ct0 = compute_ct0(ch, t0, sec_level)

        for i in range(k):
            ntt_c = ntt(np.array(c))
            tmp = np.array([barrett_reduce(ntt_c[j] * t0_ntt[i][j]) for j in range(256)])

            await wait_for_vld_addr(2 * l + 3 * k + i)
            await check_memory(dut, dut.bram1, tmp, poly_offset=2 * l + 3 * k + i)

            await wait_for_vld_addr(2 * l + 3 * k + i)
            await check_memory(dut, dut.bram1, ct0[i].to_numpy(), poly_offset=2 * l + 3 * k + i)

            valid = valid and validity_check_ct0(ct0[i].to_numpy(), sec_level)

        print(f'validity_check_ct0: {valid}')

        if not valid:
            continue

        _, valid = make_hint(r0, w, sec_level, ct0)

        print(f'validity_check_h: {valid}')

        if not valid:
            continue

        break

    for _ in range(100):
        await RisingEdge(dut.clk)

    print('bram1 finished')


async def test_dilithium_sign(dut, sec_level):
    clk = Clock(dut.clk, 1, units='us')
    cocotb.start_soon(clk.start())

    dut.rst.value = 1
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)
    await RisingEdge(dut.clk)
    dut.rst.value = 0

    await RisingEdge(dut.clk)

    for _ in range(TEST_CASES):
        mode = 0b00010000000 if sec_level == 2 else 0b01010000000 if sec_level == 3 else 0b10010000000

        pk, sk, _ = key_pair(sec_level)
        ctx = urandom(random.randint(1, 256))
        msg = urandom(random.randint(1, 800))
        rnd = b'\x00' * 32 # urandom(32)

        sig = sign(sk, msg, ctx, sec_level)

        msg = b'\x00' + len(ctx).to_bytes(1, 'little') + ctx + msg

        cocotb.start_soon(sample_inputs(dut, sk + rnd + msg, mode))

        await RisingEdge(dut.clk)

        cocotb.start_soon(bram0_checks(dut, sk, msg, rnd, sec_level)),
        cocotb.start_soon(bram1_checks(dut, sk, msg, rnd, sec_level)),
        cocotb.start_soon(data_checks(dut, sk, msg, rnd, sec_level))

        k, l = k_l(sec_level)

        kappa = 0

        while True:
            a = expand_a(sk[:32], sec_level)
            y = expand_mask(rho_prime(sk, msg, rnd), kappa, sec_level)
            kappa += 1

            w = compute_w_t(a, copy.deepcopy(y), sec_level)

            ch, w0 = compute_c(mu(sk, msg), w, sec_level)

            t0, s1, s2 = unpack_sk(sk, sec_level)
            z = compute_z(ch, y, s1, sec_level)
            r0 = compute_r0(ch, w0, s2, sec_level)
            ct0 = compute_ct0(ch, t0, sec_level)

            valid = True
            for i in range(l):
                valid = valid and validity_check_z(z[i].to_numpy(), sec_level)
            for i in range(k):
                valid = valid and validity_check_r0(r0[i].to_numpy(), sec_level)
                valid = valid and validity_check_ct0(ct0[i].to_numpy(), sec_level)

            if not valid:
                while dut.c_vld.value == 1:
                    await RisingEdge(dut.clk)
                continue

            hint, valid = make_hint(r0, w, sec_level, ct0)

            if not valid:
                while dut.c_vld.value == 1:
                    await RisingEdge(dut.clk)
                continue

            break

        z_packed = pack_z(z, sec_level)

        dut.m_axis_tready.value = 1
        await RisingEdge(dut.clk)

        for i in range(0, len(ch), 8):
            while dut.m_axis_tvalid.value != 1:
                await RisingEdge(dut.clk)

            assert dut.m_axis_tdata.value.buff == ch[i:i+8][::-1]

            dut.m_axis_tready.value = 0

            for _ in range(random.randint(0, 5)):
                await RisingEdge(dut.clk)

            dut.m_axis_tready.value = 1

            await RisingEdge(dut.clk)

        for i in range(0, len(z_packed), 8):
            while dut.m_axis_tvalid.value != 1:
                await RisingEdge(dut.clk)

            # print(dut.m_axis_tdata.value.buff.hex())
            # print(z_packed[i:i+8][::-1].hex())
            assert dut.m_axis_tdata.value.buff == z_packed[i:i+8][::-1]

            dut.m_axis_tready.value = 0

            for _ in range(random.randint(0, 5)):
                await RisingEdge(dut.clk)

            dut.m_axis_tready.value = 1

            await RisingEdge(dut.clk)

        for i in range(0, len(hint), 8):
            while dut.m_axis_tvalid.value != 1:
                await RisingEdge(dut.clk)

            # print(dut.m_axis_tdata.value.buff.hex())
            # print(bytes.fromhex(f'{hint[i + 7]:02x}{hint[i + 6]:02x}{hint[i + 5]:02x}{hint[i + 4]:02x}{hint[i + 3]:02x}{hint[i + 2]:02x}{hint[i + 1]:02x}{hint[i]:02x}').hex())
            assert dut.m_axis_tdata.value.buff == bytes.fromhex(f'{hint[i + 7]:02x}{hint[i + 6]:02x}{hint[i + 5]:02x}{hint[i + 4]:02x}{hint[i + 3]:02x}{hint[i + 2]:02x}{hint[i + 1]:02x}{hint[i]:02x}')

            dut.m_axis_tready.value = 0

            for _ in range(random.randint(0, 5)):
                await RisingEdge(dut.clk)

            dut.m_axis_tready.value = 1

            await RisingEdge(dut.clk)


@cocotb.test()
async def test_dilithium_sign2(dut):
    await test_dilithium_sign(dut, 2)

@cocotb.test()
async def test_dilithium_sign3(dut):
    await test_dilithium_sign(dut, 3)

@cocotb.test()
async def test_dilithium_sign5(dut):
    await test_dilithium_sign(dut, 5)




def run_tests():
    r = get_runner('ghdl')
    vhdl_sources = ['params_pkg.vhd', 'sample_pkg.vhd', 'reduce_pkg.vhd', 'util_comps/math_pkg.vhd', 'util_comps/small_fifo.vhd', 'util_comps/reg_ready.vhd', 'barrett_reduce.vhd', 'butterfly.vhd', 'poly_mul.vhd', 'poly_mul_state_machine.vhd', 'util_comps/bram.vhd', 'bram1_state_machine.vhd', 'sample.vhd', 'sample_in_ball.vhd', 'keccak.vhd', 'keccak_state_machine.vhd', 'encode.vhd', 'decode.vhd', 'compress.vhd', 'validity_check.vhd', 'make_hint.vhd', 'use_hint.vhd', 'out_state_machine.vhd', 'in_state_machine.vhd', 'top.vhd']
    r.build(vhdl_sources=vhdl_sources, hdl_toplevel='top', always=True, build_args=['--std=08', '-frelaxed', '-fsynopsys'])
    r.test(hdl_toplevel='top', test_module='sign_tb', test_args=['--std=08', '-frelaxed', '-fsynopsys'], parameters={'SIMULATION': True})
#     r.test(hdl_toplevel='top', test_module='sign_tb', test_args=['--std=08', '-frelaxed', '-fsynopsys'], parameters={'SIMULATION': True}, plusargs=['--vcd=test.vcd'])

if __name__ == "__main__":
    run_tests()
