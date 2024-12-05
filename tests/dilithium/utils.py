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
        while (vld_sig.value.integer >> (poly_offset << 1)) & 0x1 == 1:
            await RisingEdge(dut.clk)

        while (vld_sig.value.integer >> (poly_offset << 1)) & 0x1 != 1:
            await RisingEdge(dut.clk)

    for i in range(0, len(poly), 4):
        mem.debug_addr.value = (poly_offset * 256 + i) // 4
        await Timer(10, units='ns')
        if debug:
            print((poly_offset * 256 + i) // 4)
            print(hex(mem.debug_data.value.integer))
            print(''.join(map(lambda x: f'{x:06x}', poly[i:i + 4][:: -1])))
        assert mem.debug_data.value.integer & 0xffffff == poly[i]
        assert (mem.debug_data.value.integer >> 24) & 0xffffff == poly[i + 1]
        assert (mem.debug_data.value.integer >> 48) & 0xffffff == poly[i + 2]
        assert (mem.debug_data.value.integer >> 72) & 0xffffff == poly[i + 3]