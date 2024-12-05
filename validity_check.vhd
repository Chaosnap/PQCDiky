-- Copyright (C) 2024 Patrik Dobias <xdobia13@vut.cz>
-- Released for the non-commercial use only. For licensing, please contact <malina@vut.cz>

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.params_pkg.all;

entity validity_check is
port (
    clk: in std_logic;
    rst: in std_logic;

    -- 3 downto 2 indicates security level
    -- 1 downto 0 indicates type of validity check
    -- 00 - z ≥ gamma1 - beta
    -- 01 - r0 ≥ gamma2 - beta
    -- 10 - ct0 ≥ gamma2 + make hint
    mode: in std_logic_vector(3 downto 0);

    coeffs: in std_logic_vector(95 downto 0);
    coeffs_vld: in std_logic;

    -- indicates validity
    valid: out std_logic;
    valid_vld: out std_logic
);
end;

architecture behav of validity_check is
    signal mode_reg: std_logic_vector(3 downto 0);
    signal coeffs_reg: std_logic_vector(95 downto 0);
    signal coeffs_vld_reg: std_logic;

    signal transactions_count, transactions_count_last: natural range 0 to 511;
    signal transactions_last: std_logic;

    signal coeffs_valid, coeffs_valid_vld: std_logic;
begin
    valid <= coeffs_valid;
    valid_vld <= coeffs_valid_vld;

    with mode_reg select transactions_count_last <=
        255 when "0000",
        319 when "0100",
        447 when "1000",
        255 when "0001" | "0010",
        383 when "0101" | "0110",
        511 when "1001" | "1010",
        0 when others;

    transactions_last <= '1' when transactions_count = transactions_count_last else '0';

    process(clk) is
        variable x: signed(23 downto 0);
        variable bound: signed(19 downto 0);
    begin
        if rising_edge(clk) then
            coeffs_vld_reg <= coeffs_vld;

            if coeffs_vld = '1' then
                coeffs_reg <= coeffs;
                mode_reg <= mode;
            end if;

            case mode_reg is
                when "0000" => bound := x"1ffb2";
                when "0100" => bound := x"7ff3c";
                when "1000" => bound := x"7ff88";
                when "0001" => bound := x"173b2";
                when "0101" => bound := x"3fe3c";
                when "1001" => bound := x"3fe88";
                when "0010" => bound := x"17400";
                when "0110" => bound := x"3ff00";
                when "1010" => bound := x"3ff00";
                when others =>
            end case;

            if rst = '1' then
                coeffs_valid <= '1';
                coeffs_valid_vld <= '0';

                transactions_count <= 0;
            else
                if coeffs_vld_reg = '1' then
                    for i in 0 to 3 loop
                        x := signed(coeffs_reg(23 + 24 * i downto 24 * i));

                        if x(22) = '1' then
                            x := signed(DILITHIUM_Q) - x;
                        end if;

                        x := x - bound;

                        if x(23) = '0' then
                            coeffs_valid <= '0';
                        end if;
                    end loop;

                    if transactions_last = '1' then
                        coeffs_valid_vld <= '1';

                        transactions_count <= 0;
                    else
                        transactions_count <= transactions_count + 1;
                    end if;
                end if;

                if coeffs_valid_vld = '1' then
                    coeffs_valid <= '1';
                    coeffs_valid_vld <= '0';
                end if;
            end if;
        end if;
    end process;
end;
