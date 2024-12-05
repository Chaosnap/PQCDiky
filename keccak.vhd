-- Copyright (C) 2024 Patrik Dobias <xdobia13@vut.cz>
-- Released for the non-commercial use only. For licensing, please contact <malina@vut.cz>

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

entity keccak is
port (
    clk: in std_logic;
    rst: in std_logic;

    read_all: in std_logic;

    -- prepared message blocks
    s_axis_tdata: in std_logic_vector(63 downto 0);
    -- indicate keccak mode
    -- 00 - R = 1344 (SHAKE-128)
    -- 01 - R = 1088 (SHAKE-256)
    -- 10 - R = 1088 (SHA3-256)
    -- 11 - R = 576 (SHA3-512)
    s_axis_tuser: in std_logic_vector(1 downto 0);
    -- indicate last message block of full message
    s_axis_tlast: in std_logic;
    s_axis_tvalid: in std_logic;
    s_axis_tready: out std_logic;

    -- generated hash
    m_axis_tdata: out std_logic_vector(63 downto 0);
    m_axis_tvalid: out std_logic;
    m_axis_tready: in std_logic
);
end;

architecture behav of keccak is
    type k_plane is array(0 to 4) of std_logic_vector(63 downto 0);
    type k_state is array(0 to 4, 0 to 4) of std_logic_vector(63 downto 0);
    type k_rc is array(0 to 23) of std_logic_vector(63 downto 0);

    -- keccak state
    signal s, reg_s: k_state;

    -- round signals
    signal c, d: k_plane;
    signal theta_out, rho_pi_out, chi_iota_out: k_state;

    -- round constants
    constant RC: k_rc := (
        x"0000000000000001", x"0000000000008082", x"800000000000808A", x"8000000080008000",
        x"000000000000808B", x"0000000080000001", x"8000000080008081", x"8000000000008009",
        x"000000000000008A", x"0000000000000088", x"0000000080008009", x"000000008000000A",
        x"000000008000808B", x"800000000000008B", x"8000000000008089", x"8000000000008003",
        x"8000000000008002", x"8000000000000080", x"000000000000800A", x"800000008000000A",
        x"8000000080008081", x"8000000000008080", x"0000000080000001", x"8000000080008008"
    );

    -- state signals
    signal absorbing_msg, absorbed_msg: std_logic;
    signal computing_round: std_logic;
    signal reading_hash: std_logic;

    signal mode, mode_reg: std_logic_vector(1 downto 0);

    signal msg: std_logic_vector(63 downto 0);
    signal msg_mode: std_logic_vector(1 downto 0);
    signal msg_first, msg_last: std_logic;
    signal msg_vld: std_logic := '0';

    signal last_transaction: std_logic;
    signal current_transaction: std_logic_vector(20 downto 0);

    signal current_round: natural range 0 to 23;
begin
    s_axis_tready <= not msg_vld or absorbing_msg when rst = '0' else '0';

    proc_out: process(all) is
    begin
        m_axis_tdata <= (others => '0');

        for i in 0 to 20 loop
            if (reading_hash and current_transaction(i)) = '1' then
                m_axis_tdata <= reg_s(i mod 5, i / 5);
            end if;
        end loop;
    end process;

    m_axis_tvalid <= reading_hash;

    -- theta step

    gen_c: for x in 0 to 4 generate
        c(x) <= reg_s(x, 0) xor reg_s(x, 1) xor reg_s(x, 2) xor reg_s(x, 3) xor reg_s(x, 4);
    end generate;

    gen_d: for x in 0 to 4 generate
        d(x) <= c((x - 1) mod 5) xor (c((x + 1) mod 5) rol 1);
    end generate;

    gen_theta_x: for x in 0 to 4 generate
        gen_theta_y: for y in 0 to 4 generate
            theta_out(x, y) <= reg_s(x, y) xor d(x);
        end generate;
    end generate;

    -- rho and pi step

    rho_pi_out(0, 0) <= theta_out(0, 0);
    rho_pi_out(0, 2) <= theta_out(1, 0) rol 1;
    rho_pi_out(0, 4) <= theta_out(2, 0) rol 62;
    rho_pi_out(0, 1) <= theta_out(3, 0) rol 28;
    rho_pi_out(0, 3) <= theta_out(4, 0) rol 27;
    rho_pi_out(1, 3) <= theta_out(0, 1) rol 36;
    rho_pi_out(1, 0) <= theta_out(1, 1) rol 44;
    rho_pi_out(1, 2) <= theta_out(2, 1) rol 6;
    rho_pi_out(1, 4) <= theta_out(3, 1) rol 55;
    rho_pi_out(1, 1) <= theta_out(4, 1) rol 20;
    rho_pi_out(2, 1) <= theta_out(0, 2) rol 3;
    rho_pi_out(2, 3) <= theta_out(1, 2) rol 10;
    rho_pi_out(2, 0) <= theta_out(2, 2) rol 43;
    rho_pi_out(2, 2) <= theta_out(3, 2) rol 25;
    rho_pi_out(2, 4) <= theta_out(4, 2) rol 39;
    rho_pi_out(3, 4) <= theta_out(0, 3) rol 41;
    rho_pi_out(3, 1) <= theta_out(1, 3) rol 45;
    rho_pi_out(3, 3) <= theta_out(2, 3) rol 15;
    rho_pi_out(3, 0) <= theta_out(3, 3) rol 21;
    rho_pi_out(3, 2) <= theta_out(4, 3) rol 8;
    rho_pi_out(4, 2) <= theta_out(0, 4) rol 18;
    rho_pi_out(4, 4) <= theta_out(1, 4) rol 2;
    rho_pi_out(4, 1) <= theta_out(2, 4) rol 61;
    rho_pi_out(4, 3) <= theta_out(3, 4) rol 56;
    rho_pi_out(4, 0) <= theta_out(4, 4) rol 14;

    -- chi and iota step

    chi_iota_out(0, 0) <= rho_pi_out(0, 0) xor (not rho_pi_out(1, 0) and rho_pi_out(2, 0)) xor RC(current_round);

    gen_chi_x_y0: for x in 1 to 4 generate
        chi_iota_out(x, 0) <= rho_pi_out(x, 0) xor (not rho_pi_out((x + 1) mod 5, 0) and rho_pi_out((x + 2) mod 5, 0));
    end generate;

    gen_chi_x: for x in 0 to 4 generate
        gen_chi_y: for y in 1 to 4 generate
            chi_iota_out(x, y) <= rho_pi_out(x, y) xor (not rho_pi_out((x + 1) mod 5, y) and rho_pi_out((x + 2) mod 5, y));
        end generate;
    end generate;

    -- next state computation

    gen_in_x: for x in 0 to 4 generate
        gen_in_y: for y in 0 to 4 generate
            gen_if: if x + 5 * y < 21 generate
                s(x, y) <=
                    reg_s(x, y) xor msg when (msg_vld and absorbing_msg and current_transaction(x + 5 * y)) = '1' else
                    chi_iota_out(x, y) when computing_round = '1' else
                    reg_s(x, y);
            else generate
                s(x, y) <=
                    chi_iota_out(x, y) when computing_round = '1' else
                    reg_s(x, y);
            end generate;
        end generate;
    end generate;

    mode <= msg_mode when absorbing_msg = '1' else mode_reg;

    proc_mode: process(clk) is
    begin
        if rising_edge(clk) then
            if (rst or read_all) = '1' then
                mode_reg <= "00";
            else
                if (msg_vld and absorbing_msg) = '1' then
                    mode_reg <= msg_mode;
                end if;
            end if;
        end if;
    end process;

    with mode select last_transaction <=
        current_transaction(20) when "00",
        current_transaction(16) when "01",
        current_transaction(16) when "10",
        current_transaction(8) when "11",
        '0' when others;

    proc_msg: process(clk) is
    begin
        if rising_edge(clk) then
            if (s_axis_tvalid and (not msg_vld or absorbing_msg)) = '1' then
                msg <= s_axis_tdata;
                msg_mode <= s_axis_tuser;
                msg_last <= s_axis_tlast;
            end if;

            if rst = '1' then
                msg_vld <= '0';
            else
                if s_axis_tvalid = '1' then
                    msg_vld <= '1';
                elsif absorbing_msg = '1' then
                    msg_vld <= '0';
                end if;
            end if;

            if (rst or read_all) = '1' then
                msg_first <= '1';

                absorbing_msg <= '0';
                absorbed_msg <= '0';
            else
                if (absorbing_msg and msg_vld) = '1' then
                    msg_first <= '0';
                end if;

                if (absorbing_msg and msg_vld and (msg_last or last_transaction)) = '1' then
                    absorbing_msg <= '0';
                    absorbed_msg <= msg_last;
                elsif ((not absorbed_msg and not computing_round) or read_all)= '1' then
                    absorbing_msg <= '1';
                    absorbed_msg <= '0';
                end if;
            end if;
        end if;
    end process;

    proc_round: process(clk) is
    begin
        if rising_edge(clk) then
            if (rst or read_all) = '1' then
                computing_round <= '0';

                current_round <= 0;
            else
                if ((absorbing_msg and msg_vld and (msg_last or last_transaction)) or (reading_hash and m_axis_tready and last_transaction)) = '1' then
                    computing_round <= '1';
                elsif current_round = 23 then
                    computing_round <= '0';
                end if;

                if computing_round = '1' then
                    if current_round = 23 then
                        current_round <= 0;
                    else
                        current_round <= current_round + 1;
                    end if;
                end if;
            end if;
        end if;
    end process;

    proc_transaction: process(clk) is
    begin
        if rising_edge(clk) then
            if (rst or read_all) = '1' then
                current_transaction <= (0 => '1', others => '0');
            else
                if ((absorbing_msg and msg_vld) or (reading_hash and m_axis_tready)) = '1' then
                    if ((msg_vld and msg_last) or last_transaction) = '1' then
                        current_transaction <= (0 => '1', others => '0');
                    else
                        current_transaction <= current_transaction(current_transaction'left - 1 downto 0) & current_transaction(current_transaction'left);
                    end if;
                end if;
            end if;
        end if;
    end process;

    proc_hash: process(clk) is
    begin
        if rising_edge(clk) then
            if (rst or read_all) = '1' then
                reading_hash <= '0';
            else
                if (reading_hash and m_axis_tready and last_transaction) = '1' then
                    reading_hash <= '0';
                elsif (absorbed_msg and not computing_round) = '1' then
                    reading_hash <= '1';
                end if;
            end if;
        end if;
    end process;

    process(clk) is
    begin
        if rising_edge(clk) then
            if msg_first = '1' then
                reg_s <= (others => (others => (others => '0')));

                reg_s(0, 0) <= msg;

                if (msg_vld and absorbing_msg and msg_last) = '1' then
                    case mode is
                        when "00" => reg_s(0, 4) <= x"8000000000000000";
                        when "01" | "10" => reg_s(1, 3) <= x"8000000000000000";
                        when "11" => reg_s(3, 1) <= x"8000000000000000";
                        when others =>
                    end case;
                end if;
            else
                reg_s <= s;

                if (msg_vld and absorbing_msg and msg_last) = '1' then
                    case mode is
                        when "00" => reg_s(0, 4) <= s(0, 4) xor x"8000000000000000";
                        when "01" | "10" => reg_s(1, 3) <= s(1, 3) xor x"8000000000000000";
                        when "11" => reg_s(3, 1) <= s(3, 1) xor x"8000000000000000";
                        when others =>
                    end case;
                end if;
            end if;
        end if;
    end process;
end;
