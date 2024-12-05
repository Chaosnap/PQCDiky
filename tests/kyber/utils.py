from cocotb.clock import Timer
from cocotb.triggers import RisingEdge

async def check_data(dut, data_vld, data, debug = False):
    while data_vld.value != 1:
        await RisingEdge(dut.clk)

    if debug:
        print(data.hex())
        print(dut.DATA_DEBUG.value.buff[::-1][:len(data)].hex())

    assert dut.DATA_DEBUG.value.buff[::-1][:len(data)] == data

async def check_memory(dut, mem, poly, vld_sig = None, poly_offset = 0, debug = False):
    if vld_sig != None:
        while (vld_sig.value.integer >> poly_offset) & 0x1 == 1:
            await RisingEdge(dut.clk)

        while (vld_sig.value.integer >> poly_offset) & 0x1 != 1:
            await RisingEdge(dut.clk)
    else:
        poly_offset = int(2 * poly_offset)

    for i in range(0, len(poly), 8):
        mem.debug_addr.value = (poly_offset * 256 + i) // 8
        await Timer(10, units='ns')
        if debug:
            print((poly_offset * 256 + i) // 8)
            print(hex(mem.debug_data.value.integer))
            print(''.join(map(lambda x: f'{x:03x}', poly[i:i + 8][:: -1])))
        assert mem.debug_data.value.integer & 0xfff == poly[i]
        assert (mem.debug_data.value.integer >> 12) & 0xfff == poly[i + 1]
        assert (mem.debug_data.value.integer >> 24) & 0xfff == poly[i + 2]
        assert (mem.debug_data.value.integer >> 36) & 0xfff == poly[i + 3]
        assert (mem.debug_data.value.integer >> 48) & 0xfff == poly[i + 4]
        assert (mem.debug_data.value.integer >> 60) & 0xfff == poly[i + 5]
        assert (mem.debug_data.value.integer >> 72) & 0xfff == poly[i + 6]
        assert (mem.debug_data.value.integer >> 84) & 0xfff == poly[i + 7]