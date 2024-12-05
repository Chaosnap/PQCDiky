-- Copyright (C) 2024 Patrik Dobias <xdobia13@vut.cz>
-- Released for the non-commercial use only. For licensing, please contact <malina@vut.cz>

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

package params_pkg is
    -- KYBER parameters

    constant KYBER_Q: std_logic_vector(11 downto 0) := x"d01";

    -- helper functions
    function natural_for_sec_level(sec_level: std_logic_vector; a: natural; b: natural; c: natural) return natural;

    function std_logic_vector_for_sec_level(sec_level: std_logic_vector; a: std_logic_vector; b: std_logic_vector; c: std_logic_vector) return std_logic_vector;

    -- dimensions of matrix A (K, K)
    function kyber_k(sec_level: std_logic_vector) return natural;


    -- DILITHIUM parameters

    constant DILITHIUM_Q: std_logic_vector(23 downto 0) := x"7fe001";

    -- dimensions of matrix A (K, L)
    function dilithium_k(sec_level: std_logic_vector) return natural;
    function dilithium_l(sec_level: std_logic_vector) return natural;

    -- number of 64b transactions for dilithium c
    function dilithium_c_transactions(sec_level: std_logic_vector) return natural;
end;

package body params_pkg is
    function natural_for_sec_level(sec_level: std_logic_vector; a: natural; b: natural; c: natural) return natural is
    begin
        case sec_level is
            when "00" => return a;
            when "01" => return b;
            when others => return c;
        end case;
    end function;

    function std_logic_vector_for_sec_level(sec_level: std_logic_vector; a: std_logic_vector; b: std_logic_vector; c: std_logic_vector) return std_logic_vector is
    begin
        case sec_level is
            when "00" => return a;
            when "01" => return b;
            when others => return c;
        end case;
    end function;

    function kyber_k(sec_level: std_logic_vector) return natural is
    begin
        return natural_for_sec_level(sec_level, 2, 3, 4);
    end function;

    function dilithium_k(sec_level: std_logic_vector) return natural is
    begin
        return natural_for_sec_level(sec_level, 4, 6, 8);
    end function;

    function dilithium_l(sec_level: std_logic_vector) return natural is
    begin
        return natural_for_sec_level(sec_level, 4, 5, 7);
    end function;

    function dilithium_c_transactions(sec_level: std_logic_vector) return natural is
    begin
        return natural_for_sec_level(sec_level, 4, 6, 8);
    end function;
end;
