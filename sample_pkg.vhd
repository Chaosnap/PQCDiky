-- Copyright (C) 2024 Patrik Dobias <xdobia13@vut.cz>
-- Released for the non-commercial use only. For licensing, please contact <malina@vut.cz>

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.params_pkg.all;

package sample_pkg is
    -- cbd sampling for kyber ETA = 2, samples 8 coefficients at a time
    -- as sampled coeefs are in small range <-2; 2> it will only output mux value that will be later used to select correct value for every coeff
    procedure sample_cbd2(signal bytes: in std_logic_vector(31 downto 0); signal coeffs_mux: out std_logic_vector(23 downto 0));

    -- cbd sampling for kyber ETA = 3, samples 8 coefficients at a time
    -- as sampled coeefs are in small range <-3; 3> it will only output mux value that will be later used to select correct value for every coeff
    procedure sample_cbd3(signal bytes: in std_logic_vector(47 downto 0); signal coeffs_mux: out std_logic_vector(23 downto 0));

    -- rejection of 2 (4) coefficients for dilithium (kyber) matrix A expansion
    function rej_ntt(bytes: std_logic_vector(47 downto 0); mode: std_logic) return std_logic_vector;

    -- rejection for s1, s2 expansion, dilithium ETA = 2, rejects 4 coefficients at a time
    -- as sampled coeefs are in small range <-2; 2> it will only output mux value that will be later used to select correct value for every coeff
    procedure rej_bounded2(signal bytes: in std_logic_vector(15 downto 0); signal coeffs_mux: out std_logic_vector(11 downto 0); signal coeffs_mux_count_vld: out natural range 0 to 4);

    -- rejection for s1, s2 expansion, dilithium ETA = 4, rejects 4 coefficients at a time
    -- as sampled coeefs are in small range <-4; 4> it will only output mux value that will be later used to select correct value for every coeff
    procedure rej_bounded4(signal bytes: in std_logic_vector(15 downto 0); signal coeffs_mux: out std_logic_vector(15 downto 0); signal coeffs_mux_count_vld: out natural range 0 to 4);

    -- make sure rejected coefficients are valid from LSB
    procedure reorder_rej_ntt(signal coeffs: in std_logic_vector(47 downto 0); signal coeffs_vld: in std_logic_vector(3 downto 0); signal coeffs_reordered: out std_logic_vector(47 downto 0); signal coeffs_reordered_count_vld: out natural range 0 to 4);
end;

package body sample_pkg is
    procedure sample_cbd2(signal bytes: in std_logic_vector(31 downto 0); signal coeffs_mux: out std_logic_vector(23 downto 0)) is
    begin
        for i in 0 to 7 loop
            case bytes(3 + 4 * i downto 4 * i) is
                when "0001" | "0010" | "0111" | "1011" =>
                    coeffs_mux(2 + 3 * i downto 3 * i) <= "001";
                when "0011" =>
                    coeffs_mux(2 + 3 * i downto 3 * i) <= "010";
                when "0100" | "1000" | "1101" | "1110" =>
                    coeffs_mux(2 + 3 * i downto 3 * i) <= "111";
                when "1100" =>
                    coeffs_mux(2 + 3 * i downto 3 * i) <= "110";
                when others =>
                    coeffs_mux(2 + 3 * i downto 3 * i) <= "000";
            end case;
        end loop;
    end procedure;

    procedure sample_cbd3(signal bytes: in std_logic_vector(47 downto 0); signal coeffs_mux: out std_logic_vector(23 downto 0)) is
    begin
        for i in 0 to 7 loop
            case bytes(5 + 6 * i downto 6 * i) is
                when "000001" | "000010" | "000100" | "001011" | "010011" | "100011" | "001101" | "010101" | "100101" | "001110" | "010110" | "100110" | "011111" | "101111" | "110111" =>
                    coeffs_mux(2 + 3 * i downto 3 * i) <= "001";
                when "000011" | "000101" | "000110" | "001111" | "010111" | "100111" =>
                    coeffs_mux(2 + 3 * i downto 3 * i) <= "010";
                when "000111" =>
                    coeffs_mux(2 + 3 * i downto 3 * i) <= "011";
                when "001000" | "010000" | "100000" | "011001" | "011010" | "011100" | "101001" | "101010" | "101100" | "110001" | "110010" | "110100" | "111011" | "111101" | "111110" =>
                    coeffs_mux(2 + 3 * i downto 3 * i) <= "111";
                when "011000" | "101000" | "110000" | "111001" | "111010" | "111100" =>
                    coeffs_mux(2 + 3 * i downto 3 * i) <= "110";
                when "111000" =>
                    coeffs_mux(2 + 3 * i downto 3 * i) <= "101";
                when others =>
                    coeffs_mux(2 + 3 * i downto 3 * i) <= "000";
            end case;
        end loop;
    end procedure;

    function rej_ntt(bytes: std_logic_vector(47 downto 0); mode: std_logic) return std_logic_vector is
        variable q: signed(25 downto 0);
        variable sum: signed(25 downto 0);

        variable coeffs_vld: std_logic_vector(3 downto 0);
    begin
        if mode = '1' then
            q := signed('0' & DILITHIUM_Q(23 downto 12) & '0' & DILITHIUM_Q(11 downto 0));
        else
            q := signed('0' & KYBER_Q & '0' & KYBER_Q);
        end if;

        for i in 0 to 1 loop
            sum := signed('0' & (bytes(23 + 24 * i) and (not mode)) & bytes(22 + 24 * i downto 12 + 24 * i) & not mode & bytes(11 + 24 * i downto 24 * i)) - q;

            coeffs_vld(2 * i) := ((not sum(12)) and (not mode)) or (mode and sum(25));
            coeffs_vld(1 + 2 * i) := sum(25);
        end loop;

        return coeffs_vld;
    end function;

    procedure rej_bounded2(signal bytes: in std_logic_vector(15 downto 0); signal coeffs_mux: out std_logic_vector(11 downto 0); signal coeffs_mux_count_vld: out natural range 0 to 4) is
        variable coeffs_mux_tmp: std_logic_vector(11 downto 0);
        variable coeffs_mux_vld_tmp: std_logic_vector(3 downto 0);
    begin
        for i in 0 to 3 loop
            -- is < 15?
            coeffs_mux_vld_tmp(i) := not (and bytes(3 + 4 * i downto 4 * i));

            case bytes(3 + 4 * i downto 4 * i) is
                when "0001" | "0110" | "1011" => coeffs_mux_tmp(2 + 3 * i downto 3 * i) := "001";
                when "0000" | "0101" | "1010" => coeffs_mux_tmp(2 + 3 * i downto 3 * i) := "010";
                when "0011" | "1000" | "1101" => coeffs_mux_tmp(2 + 3 * i downto 3 * i) := "111";
                when "0100" | "1001" | "1110" => coeffs_mux_tmp(2 + 3 * i downto 3 * i) := "110";
                when others => coeffs_mux_tmp(2 + 3 * i downto 3 * i) := "000";
            end case;
        end loop;

        case coeffs_mux_vld_tmp is
            when "0010" => coeffs_mux <= coeffs_mux_tmp(11 downto 3) & coeffs_mux_tmp(5 downto 3);
            when "0100" => coeffs_mux <= coeffs_mux_tmp(11 downto 3) & coeffs_mux_tmp(8 downto 6);
            when "0101" => coeffs_mux <= coeffs_mux_tmp(11 downto 6) & coeffs_mux_tmp(8 downto 6) & coeffs_mux_tmp(2 downto 0);
            when "0110" => coeffs_mux <= coeffs_mux_tmp(11 downto 6) & coeffs_mux_tmp(8 downto 3);
            when "1000" => coeffs_mux <= coeffs_mux_tmp(11 downto 3) & coeffs_mux_tmp(11 downto 9);
            when "1001" => coeffs_mux <= coeffs_mux_tmp(11 downto 6) & coeffs_mux_tmp(11 downto 9) & coeffs_mux_tmp(2 downto 0);
            when "1010" => coeffs_mux <= coeffs_mux_tmp(11 downto 6) & coeffs_mux_tmp(11 downto 9) & coeffs_mux_tmp(5 downto 3);
            when "1011" => coeffs_mux <= coeffs_mux_tmp(11 downto 9) & coeffs_mux_tmp(11 downto 9) & coeffs_mux_tmp(5 downto 0);
            when "1100" => coeffs_mux <= coeffs_mux_tmp(11 downto 6) & coeffs_mux_tmp(11 downto 6);
            when "1101" => coeffs_mux <= coeffs_mux_tmp(11 downto 9) & coeffs_mux_tmp(11 downto 6) & coeffs_mux_tmp(2 downto 0);
            when "1110" => coeffs_mux <= coeffs_mux_tmp(11 downto 9) & coeffs_mux_tmp(11 downto 3);
            when others => coeffs_mux <= coeffs_mux_tmp;
        end case;

        case coeffs_mux_vld_tmp is
            when "0001" | "0010" | "0100" | "1000" => coeffs_mux_count_vld <= 1;
            when "0011" | "0101" | "0110" | "1001" | "1010" | "1100" => coeffs_mux_count_vld <= 2;
            when "0111" | "1011" | "1101" | "1110" => coeffs_mux_count_vld <= 3;
            when "1111" => coeffs_mux_count_vld <= 4;
            when others => coeffs_mux_count_vld <= 0;
        end case;
    end procedure;

    procedure rej_bounded4(signal bytes: in std_logic_vector(15 downto 0); signal coeffs_mux: out std_logic_vector(15 downto 0); signal coeffs_mux_count_vld: out natural range 0 to 4) is
        variable coeffs_mux_tmp: std_logic_vector(15 downto 0);
        variable coeffs_mux_vld_tmp: std_logic_vector(3 downto 0);
    begin
        for i in 0 to 3 loop
            -- is < 9?
            coeffs_mux_vld_tmp(i) := not (bytes(3 + 4 * i) and (or bytes(2 + 4 * i downto 4 * i)));

            case bytes(3 + 4 * i downto 4 * i) is
                when "0011" => coeffs_mux_tmp(3 + 4 * i downto 4 * i) := "0001";
                when "0010" => coeffs_mux_tmp(3 + 4 * i downto 4 * i) := "0010";
                when "0001" => coeffs_mux_tmp(3 + 4 * i downto 4 * i) := "0011";
                when "0000" => coeffs_mux_tmp(3 + 4 * i downto 4 * i) := "0100";
                when "0101" => coeffs_mux_tmp(3 + 4 * i downto 4 * i) := "1111";
                when "0110" => coeffs_mux_tmp(3 + 4 * i downto 4 * i) := "1110";
                when "0111" => coeffs_mux_tmp(3 + 4 * i downto 4 * i) := "1101";
                when "1000" => coeffs_mux_tmp(3 + 4 * i downto 4 * i) := "1100";
                when others => coeffs_mux_tmp(3 + 4 * i downto 4 * i) := "0000";
            end case;
        end loop;

        case coeffs_mux_vld_tmp is
            when "0010" => coeffs_mux <= coeffs_mux_tmp(15 downto 4) & coeffs_mux_tmp(7 downto 4);
            when "0100" => coeffs_mux <= coeffs_mux_tmp(15 downto 4) & coeffs_mux_tmp(11 downto 8);
            when "0101" => coeffs_mux <= coeffs_mux_tmp(15 downto 8) & coeffs_mux_tmp(11 downto 8) & coeffs_mux_tmp(3 downto 0);
            when "0110" => coeffs_mux <= coeffs_mux_tmp(15 downto 8) & coeffs_mux_tmp(11 downto 4);
            when "1000" => coeffs_mux <= coeffs_mux_tmp(15 downto 4) & coeffs_mux_tmp(15 downto 12);
            when "1001" => coeffs_mux <= coeffs_mux_tmp(15 downto 8) & coeffs_mux_tmp(15 downto 12) & coeffs_mux_tmp(3 downto 0);
            when "1010" => coeffs_mux <= coeffs_mux_tmp(15 downto 8) & coeffs_mux_tmp(15 downto 12) & coeffs_mux_tmp(7 downto 4);
            when "1011" => coeffs_mux <= coeffs_mux_tmp(15 downto 12) & coeffs_mux_tmp(15 downto 12) & coeffs_mux_tmp(7 downto 0);
            when "1100" => coeffs_mux <= coeffs_mux_tmp(15 downto 8) & coeffs_mux_tmp(15 downto 8);
            when "1101" => coeffs_mux <= coeffs_mux_tmp(15 downto 12) & coeffs_mux_tmp(15 downto 8) & coeffs_mux_tmp(3 downto 0);
            when "1110" => coeffs_mux <= coeffs_mux_tmp(15 downto 12) & coeffs_mux_tmp(15 downto 4);
            when others => coeffs_mux <= coeffs_mux_tmp;
        end case;

        case coeffs_mux_vld_tmp is
            when "0001" | "0010" | "0100" | "1000" => coeffs_mux_count_vld <= 1;
            when "0011" | "0101" | "0110" | "1001" | "1010" | "1100" => coeffs_mux_count_vld <= 2;
            when "0111" | "1011" | "1101" | "1110" => coeffs_mux_count_vld <= 3;
            when "1111" => coeffs_mux_count_vld <= 4;
            when others => coeffs_mux_count_vld <= 0;
        end case;
    end procedure;

    procedure reorder_rej_ntt(signal coeffs: in std_logic_vector(47 downto 0); signal coeffs_vld: in std_logic_vector(3 downto 0); signal coeffs_reordered: out std_logic_vector(47 downto 0); signal coeffs_reordered_count_vld: out natural range 0 to 4) is
    begin
        case coeffs_vld is
            when "0010" => coeffs_reordered <= coeffs(47 downto 12) & coeffs(23 downto 12);
            when "0100" => coeffs_reordered <= coeffs(47 downto 12) & coeffs(35 downto 24);
            when "0101" => coeffs_reordered <= coeffs(47 downto 24) & coeffs(35 downto 24) & coeffs(11 downto 0);
            when "0110" => coeffs_reordered <= coeffs(47 downto 24) & coeffs(35 downto 12);
            when "1000" => coeffs_reordered <= coeffs(47 downto 12) & coeffs(47 downto 36);
            when "1001" => coeffs_reordered <= coeffs(47 downto 24) & coeffs(47 downto 36) & coeffs(11 downto 0);
            when "1010" => coeffs_reordered <= coeffs(47 downto 24) & coeffs(47 downto 36) & coeffs(23 downto 12);
            when "1011" => coeffs_reordered <= coeffs(47 downto 36) & coeffs(47 downto 36) & coeffs(23 downto 0);
            when "1100" => coeffs_reordered <= coeffs(47 downto 24) & coeffs(47 downto 24);
            when "1101" => coeffs_reordered <= coeffs(47 downto 36) & coeffs(47 downto 24) & coeffs(11 downto 0);
            when "1110" => coeffs_reordered <= coeffs(47 downto 36) & coeffs(47 downto 12);
            when others => coeffs_reordered <= coeffs;
        end case;

        case coeffs_vld is
            when "0001" | "0010" | "0100" | "1000" => coeffs_reordered_count_vld <= 1;
            when "0011" | "0101" | "0110" | "1001" | "1010" | "1100" => coeffs_reordered_count_vld <= 2;
            when "0111" | "1011" | "1101" | "1110" => coeffs_reordered_count_vld <= 3;
            when "1111" => coeffs_reordered_count_vld <= 4;
            when others => coeffs_reordered_count_vld <= 0;
        end case;
    end procedure;
end;
