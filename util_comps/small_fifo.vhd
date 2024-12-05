-- Copyright (C) 2024 Patrik Dobias <xdobia13@vut.cz>
-- Released for the non-commercial use only. For licensing, please contact <malina@vut.cz>

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.math_pkg.all;

entity small_fifo is
generic (
    DATA_WIDTH: natural := 96;
    DATA_DEPTH: natural := 64
);
port (
    clk: in std_logic;
    rst: in std_logic;

    din: in std_logic_vector(DATA_WIDTH - 1 downto 0);
    din_vld: in std_logic;

    dout: out std_logic_vector(DATA_WIDTH - 1 downto 0);
    dout_vld: out std_logic;
    dout_rdy: in std_logic
);
end;

architecture behav of small_fifo is
    type fifo_t is array(integer range <>) of std_logic_vector(DATA_WIDTH - 1 downto 0);
    signal fifo: fifo_t(DATA_DEPTH - 1 downto 0) := (others => (others => '0'));

    signal full: std_logic;

    signal fifo_r_index, fifo_w_index: unsigned(log2(DATA_DEPTH) - 1 downto 0) := (others => '0');
begin
    dout <= fifo(to_integer(fifo_r_index));
    dout_vld <= '1' when fifo_r_index /= fifo_w_index else full;

    process(clk) is
    begin
        if rising_edge(clk) then
            if din_vld = '1' then
                fifo(to_integer(fifo_w_index)) <= din;
            end if;

            if rst = '1' then
                full <= '0';

                fifo_r_index <= (others => '0');
                fifo_w_index <= (others => '0');
            else
                if din_vld = '1' then
                    if (dout_vld and dout_rdy) = '0' and fifo_w_index + 1 = fifo_r_index then
                        full <= '1';
                    end if;

                    fifo_w_index <= fifo_w_index + 1;
                end if;

                if (dout_vld and dout_rdy) = '1' then
                    full <= full and din_vld;

                    fifo_r_index <= fifo_r_index + 1;
                end if;
            end if;
        end if;
    end process;
end;