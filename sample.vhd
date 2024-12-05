-- Copyright (C) 2024 Patrik Dobias <xdobia13@vut.cz>
-- Released for the non-commercial use only. For licensing, please contact <malina@vut.cz>

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.params_pkg.all;
use work.sample_pkg.all;

-- samples coefficients from bytes
entity sample is
port (
    clk: in std_logic;
    rst: in std_logic;

    -- data from keccak that should be used during sampling
    s_axis_tdata: in std_logic_vector(63 downto 0);
    -- indicates, which sampling should be used
    -- 000 - sample NTT (kyber) - input shake-128
    -- 001 - sample cbd ETA=2 (kyber) - input shake-256
    -- 010 - sample cbd ETA=3 (kyber) - input shake-256
    -- 100 - sample NTT (dilithium) - input shake-128
    -- 101 - sample bounded ETA=2 (dilithium) - input shake-256
    -- 110 - sample bounded ETA=4 (dilithium) - input shake-256
    s_axis_tuser: in std_logic_vector(2 downto 0);
    s_axis_tvalid: in std_logic;
    s_axis_tready: out std_logic;

    -- sampled coefficients 8 (4) at a time for kyber (dilithium)
    m_axis_tdata: out std_logic_vector(95 downto 0);
    m_axis_tuser: out std_logic_vector(2 downto 0);
    -- indicates that all 256 coefficients were sampled
    m_axis_tlast: out std_logic;
    m_axis_tvalid: out std_logic;
    m_axis_tready: in std_logic
);
end;

architecture behav of sample is
    type x3b_shift_reg_t is array(natural range <>) of std_logic_vector(2 downto 0);

    signal reg_ready_m_axis_tdata: std_logic_vector(63 downto 0);
    signal reg_ready_m_axis_tuser: std_logic_vector(2 downto 0);
    signal reg_ready_m_axis_tvalid, reg_ready_m_axis_tready: std_logic;

    -- bytes selection from incoming data
    signal bytes: std_logic_vector(79 downto 0);
    signal bytes_mux: std_logic_vector(2 downto 0);
    signal bytes_vld, bytes_next: std_logic;

    -- reject NTT signals
    signal rej_ntt_coeffs, rej_ntt_coeffs_reordered: std_logic_vector(47 downto 0);
    signal rej_ntt_coeffs_vld: std_logic_vector(3 downto 0);
    signal rej_ntt_coeffs_reordered_count_vld: natural range 0 to 4;

    -- as we want to output 8 (4) coeffs at a time, we need to store them in registers until 8 (4) coeffs are valid for kyber (dilithium)
    signal rej_ntt_valid_coeffs: std_logic_vector(131 downto 0);
    signal rej_ntt_valid_coeffs_count_vld: natural range 0 to 11;
    signal rej_ntt_valid_coeffs_vld: std_logic;

    -- CBD sampling signals
    -- as sampled coeefs are in small range <-2; 2> it will only output mux value that will be later used to select correct value for every coeff
    signal sample_cbd2_coeffs_mux, sample_cbd3_coeffs_mux, sample_cbd_coeffs_mux: std_logic_vector(23 downto 0);
    signal sample_cbd_coeffs: std_logic_vector(95 downto 0);
    signal sample_cbd_coeffs_vld: std_logic;

    -- bounded rejection signals
    -- as sampled coeefs are in small range <-2; 2> it will only output mux value that will be later used to select correct value for every coeff
    signal rej_bounded2_coeffs_mux: std_logic_vector(11 downto 0);
    signal rej_bounded4_coeffs_mux: std_logic_vector(15 downto 0);
    signal rej_bounded2_coeffs_mux_count_vld, rej_bounded4_coeffs_mux_count_vld: natural range 0 to 4;

    signal rej_bounded_coeffs_mux: std_logic_vector(15 downto 0);
    signal rej_bounded_coeffs_mux_count_vld: natural range 0 to 4;

    -- as we want to output 4 coeffs at a time, we need to store them in registers until 4 coeffs are valid
    -- as sampled coeefs are in small range <-4; 4> it will only output mux value that will be later used to select correct value for every coeff
    signal rej_bounded_valid_coeffs_mux: std_logic_vector(27 downto 0);
    signal rej_bounded_valid_coeffs_mux_count_vld: natural range 0 to 7;

    signal rej_bounded_coeffs: std_logic_vector(95 downto 0);
    signal rej_bounded_coeffs_vld: std_logic;

    -- indicates rejection can read new bytes
    signal rej_next: std_logic;

    -- rejected coefficients
    signal coeffs, coeffs_reg: std_logic_vector(95 downto 0);
    signal coeffs_vld, coeffs_vld_reg, coeffs_next: std_logic;

    signal coeffs_count: natural range 0 to 63;
    signal coeffs_count_last, coeffs_count_last_reg: std_logic;

    signal mode_shift_reg: x3b_shift_reg_t(2 downto 0);
begin
    m_axis_tdata <= coeffs_reg;
    m_axis_tuser <= mode_shift_reg(0);
    m_axis_tlast <= coeffs_count_last_reg;
    m_axis_tvalid <= coeffs_vld_reg;

    reg_ready: entity work.reg_ready
    generic map (
        DATA_WIDTH => 64,
        USER_WIDTH => 3
    )
    port map (
        clk => clk,
        rst => rst,

        s_axis_tdata => s_axis_tdata,
        s_axis_tuser => s_axis_tuser,
        s_axis_tvalid => s_axis_tvalid,
        s_axis_tready => s_axis_tready,

        m_axis_tdata => reg_ready_m_axis_tdata,
        m_axis_tuser => reg_ready_m_axis_tuser,
        m_axis_tvalid => reg_ready_m_axis_tvalid,
        m_axis_tready => reg_ready_m_axis_tready
    );

    reg_ready_m_axis_tready <= '1' when (coeffs_vld_reg and coeffs_count_last_reg and m_axis_tready) = '1' else bytes_next;

    with bytes_mux select bytes_next <=
        (not bytes_vld or rej_next) when "100" | "001" | "011" | "111",
        (not bytes_vld or rej_next) and ((not reg_ready_m_axis_tuser(1) and not reg_ready_m_axis_tuser(0)) or (not reg_ready_m_axis_tuser(2) and reg_ready_m_axis_tuser(1))) when "000",
        '0' when others;

    -- select bytes at given offset from incoming data
    proc_bytes: process(clk) is
    begin
        if rising_edge(clk) then
            if (reg_ready_m_axis_tvalid and (not bytes_vld or rej_next)) = '1' then
                case bytes_mux is
                    when "000" => bytes(63 downto 0) <= reg_ready_m_axis_tdata;
                    when "001" => bytes(79 downto 0) <= reg_ready_m_axis_tdata & bytes(63 downto 48);
                    when "010" => bytes(47 downto 0) <= reg_ready_m_axis_tdata(15 downto 0) & bytes(79 downto 48);
                    when "011" => bytes(47 downto 0) <= reg_ready_m_axis_tdata(63 downto 16);
                    when "100" => bytes(31 downto 0) <= reg_ready_m_axis_tdata(63 downto 32);
                    when "101" => bytes(15 downto 0) <= reg_ready_m_axis_tdata(31 downto 16);
                    when "110" => bytes(15 downto 0) <= reg_ready_m_axis_tdata(47 downto 32);
                    when others => bytes(15 downto 0) <= reg_ready_m_axis_tdata(63 downto 48);
                end case;
            end if;

            if (rst or coeffs_count_last_reg or (coeffs_count_last and coeffs_vld)) = '1' then
                bytes_vld <= '0';
                bytes_mux <= "000";
            else
                if reg_ready_m_axis_tvalid = '1' then
                    bytes_vld <= '1';
                elsif rej_next = '1' then
                    bytes_vld <= '0';
                end if;

                if (reg_ready_m_axis_tvalid and (not bytes_vld or rej_next)) = '1' then
                    case bytes_mux is
                        when "000" =>
                            case reg_ready_m_axis_tuser is
                                when "001" => bytes_mux <= "100";
                                when "101" | "110" => bytes_mux <= "101";
                                when others => bytes_mux <= "001";
                            end case;
                        -- shift by 6B
                        when "001" => bytes_mux <= "010";
                        -- shift by 6B
                        when "010" => bytes_mux <= "011";
                        -- shift by 2B
                        when "101" => bytes_mux <= "110";
                        -- shift by 2B
                        when "110" => bytes_mux <= "111";
                        when others => bytes_mux <= "000";
                    end case;
                end if;
            end if;
        end if;
    end process;

    -- reordering of NTT rejection based on selected mode
    rej_ntt_coeffs <= (bytes(47) and (not mode_shift_reg(mode_shift_reg'left)(2))) & bytes(46 downto 24) &
                      (bytes(23) and (not mode_shift_reg(mode_shift_reg'left)(2))) & bytes(22 downto 0);
    rej_ntt_coeffs_vld <= rej_ntt(bytes(47 downto 0), mode_shift_reg(mode_shift_reg'left)(2));

    reorder_rej_ntt(rej_ntt_coeffs, rej_ntt_coeffs_vld, rej_ntt_coeffs_reordered, rej_ntt_coeffs_reordered_count_vld);

    rej_ntt_valid_coeffs_vld <= '1' when rej_ntt_valid_coeffs_count_vld > 7 else '0';

    proc_rej_ntt: process(clk) is
    begin
        if rising_edge(clk) then
            if mode_shift_reg(mode_shift_reg'left)(1 downto 0) = "00" then
                if rej_ntt_valid_coeffs_count_vld = 11 then if coeffs_next = '1' then rej_ntt_valid_coeffs(83 downto 0) <= rej_ntt_coeffs_reordered & rej_ntt_valid_coeffs(131 downto 96); end if;
                elsif rej_ntt_valid_coeffs_count_vld = 10 then if coeffs_next = '1' then rej_ntt_valid_coeffs(71 downto 0) <= rej_ntt_coeffs_reordered & rej_ntt_valid_coeffs(119 downto 96); end if;
                elsif rej_ntt_valid_coeffs_count_vld = 9 then if coeffs_next = '1' then rej_ntt_valid_coeffs(59 downto 0) <= rej_ntt_coeffs_reordered & rej_ntt_valid_coeffs(107 downto 96); end if;
                elsif rej_ntt_valid_coeffs_count_vld = 8 then if coeffs_next = '1' then rej_ntt_valid_coeffs(47 downto 0) <= rej_ntt_coeffs_reordered; end if;
                elsif rej_ntt_valid_coeffs_count_vld = 7 then rej_ntt_valid_coeffs(131 downto 0) <= rej_ntt_coeffs_reordered & rej_ntt_valid_coeffs(83 downto 0);
                elsif rej_ntt_valid_coeffs_count_vld = 6 then rej_ntt_valid_coeffs(119 downto 0) <= rej_ntt_coeffs_reordered & rej_ntt_valid_coeffs(71 downto 0);
                elsif rej_ntt_valid_coeffs_count_vld = 5 then rej_ntt_valid_coeffs(107 downto 0) <= rej_ntt_coeffs_reordered & rej_ntt_valid_coeffs(59 downto 0);
                elsif rej_ntt_valid_coeffs_count_vld = 4 then rej_ntt_valid_coeffs(95 downto 0) <= rej_ntt_coeffs_reordered & rej_ntt_valid_coeffs(47 downto 0);
                elsif rej_ntt_valid_coeffs_count_vld = 3 then rej_ntt_valid_coeffs(83 downto 0) <= rej_ntt_coeffs_reordered & rej_ntt_valid_coeffs(35 downto 0);
                elsif rej_ntt_valid_coeffs_count_vld = 2 then rej_ntt_valid_coeffs(71 downto 0) <= rej_ntt_coeffs_reordered & rej_ntt_valid_coeffs(23 downto 0);
                elsif rej_ntt_valid_coeffs_count_vld = 1 then rej_ntt_valid_coeffs(59 downto 0) <= rej_ntt_coeffs_reordered & rej_ntt_valid_coeffs(11 downto 0);
                else rej_ntt_valid_coeffs(47 downto 0) <= rej_ntt_coeffs_reordered;
                end if;
            end if;

            if (rst or (coeffs_count_last and coeffs_vld and coeffs_next)) = '1' then
                rej_ntt_valid_coeffs_count_vld <= 0;
            elsif mode_shift_reg(mode_shift_reg'left)(1 downto 0) = "00" then
                if rej_next = '1' then
                    if bytes_vld = '1' then
                        -- if 8 (4 for dilithium) coeffs are valid we will read them, so next cycle they will be invalidated
                        if rej_ntt_valid_coeffs_vld = '1' then
                            rej_ntt_valid_coeffs_count_vld <= rej_ntt_valid_coeffs_count_vld - 8 + rej_ntt_coeffs_reordered_count_vld;
                        else
                            rej_ntt_valid_coeffs_count_vld <= rej_ntt_valid_coeffs_count_vld + rej_ntt_coeffs_reordered_count_vld;
                        end if;
                    -- if 8 (4 for dilithium) coeffs are valid we will read them, so next cycle they will be invalidated
                    elsif rej_ntt_valid_coeffs_vld = '1' then
                        rej_ntt_valid_coeffs_count_vld <= rej_ntt_valid_coeffs_count_vld - 8;
                    end if;
                end if;
            end if;
        end if;
    end process;

    sample_cbd2(bytes(31 downto 0), sample_cbd2_coeffs_mux);
    sample_cbd3(bytes(47 downto 0), sample_cbd3_coeffs_mux);

    gen_sample_cbd_coeffs: for i in 0 to 7 generate
        with sample_cbd_coeffs_mux(2 + 3 * i downto 3 * i) select sample_cbd_coeffs(11 + 12 * i downto 12 * i) <=
            x"001" when "001",
            x"002" when "010",
            x"003" when "011",
            x"d00" when "111",
            x"cff" when "110",
            x"cfe" when "101",
            x"000" when others;
    end generate;

    proc_cbd: process(clk) is
    begin
        if rising_edge(clk) then
            if (rst or (coeffs_count_last and coeffs_vld and coeffs_next)) = '1' then
                sample_cbd_coeffs_vld <= '0';
            else
                if bytes_vld = '1' then
                    sample_cbd_coeffs_vld <= bytes_vld;
                elsif coeffs_next = '1' then
                    sample_cbd_coeffs_vld <= '0';
                end if;
            end if;

            if (not sample_cbd_coeffs_vld or coeffs_next) = '1' then
                if mode_shift_reg(mode_shift_reg'left) = "001" then
                    sample_cbd_coeffs_mux <= sample_cbd2_coeffs_mux;
                elsif mode_shift_reg(mode_shift_reg'left) = "010" then
                    sample_cbd_coeffs_mux <= sample_cbd3_coeffs_mux;
                end if;
            end if;
        end if;
    end process;

    rej_bounded2(bytes(15 downto 0), rej_bounded2_coeffs_mux, rej_bounded2_coeffs_mux_count_vld);
    rej_bounded4(bytes(15 downto 0), rej_bounded4_coeffs_mux, rej_bounded4_coeffs_mux_count_vld);

    rej_bounded_coeffs_mux_count_vld <= rej_bounded2_coeffs_mux_count_vld when mode_shift_reg(mode_shift_reg'left)(0) = '1' else rej_bounded4_coeffs_mux_count_vld;

    gen_rej_bounded_coeffs_mux: for i in 0 to 3 generate
        rej_bounded_coeffs_mux(3 + 4 * i downto 4 * i) <= rej_bounded2_coeffs_mux(2 + 3 * i) & rej_bounded2_coeffs_mux(2 + 3 * i downto 3 * i) when mode_shift_reg(mode_shift_reg'left)(0) = '1' else
            rej_bounded4_coeffs_mux(3 + 4 * i downto 4 * i);
    end generate;

    rej_bounded_coeffs_vld <= '1' when rej_bounded_valid_coeffs_mux_count_vld > 3 else '0';

    gen_rej_bounded_coeffs: for i in 0 to 3 generate
        with rej_bounded_valid_coeffs_mux(3 + 4 * i downto 4 * i) select rej_bounded_coeffs(23 + 24 * i downto 24 * i) <=
            x"000001" when "0001",
            x"000002" when "0010",
            x"000003" when "0011",
            x"000004" when "0100",
            x"7fe000" when "1111",
            x"7fdfff" when "1110",
            x"7fdffe" when "1101",
            x"7fdffd" when "1100",
            x"000000" when others;
    end generate;

    proc_rej_bounded: process(clk) is
    begin
        if rising_edge(clk) then
            if mode_shift_reg(mode_shift_reg'left) = "101" or mode_shift_reg(mode_shift_reg'left) = "110" then
                if rej_bounded_valid_coeffs_mux_count_vld = 7 then if coeffs_next = '1' then rej_bounded_valid_coeffs_mux(27 downto 0) <= rej_bounded_coeffs_mux & rej_bounded_valid_coeffs_mux(27 downto 16); end if;
                elsif rej_bounded_valid_coeffs_mux_count_vld = 6 then if coeffs_next = '1' then rej_bounded_valid_coeffs_mux(23 downto 0) <= rej_bounded_coeffs_mux & rej_bounded_valid_coeffs_mux(23 downto 16); end if;
                elsif rej_bounded_valid_coeffs_mux_count_vld = 5 then if coeffs_next = '1' then rej_bounded_valid_coeffs_mux(19 downto 0) <= rej_bounded_coeffs_mux & rej_bounded_valid_coeffs_mux(19 downto 16); end if;
                elsif rej_bounded_valid_coeffs_mux_count_vld = 4 then if coeffs_next = '1' then rej_bounded_valid_coeffs_mux(15 downto 0) <= rej_bounded_coeffs_mux; end if;
                elsif rej_bounded_valid_coeffs_mux_count_vld = 3 then rej_bounded_valid_coeffs_mux(27 downto 0) <= rej_bounded_coeffs_mux & rej_bounded_valid_coeffs_mux(11 downto 0);
                elsif rej_bounded_valid_coeffs_mux_count_vld = 2 then rej_bounded_valid_coeffs_mux(23 downto 0) <= rej_bounded_coeffs_mux & rej_bounded_valid_coeffs_mux(7 downto 0);
                elsif rej_bounded_valid_coeffs_mux_count_vld = 1 then rej_bounded_valid_coeffs_mux(19 downto 0) <= rej_bounded_coeffs_mux & rej_bounded_valid_coeffs_mux(3 downto 0);
                else rej_bounded_valid_coeffs_mux(15 downto 0) <= rej_bounded_coeffs_mux;
                end if;
            end if;

            if (rst or (coeffs_count_last and coeffs_vld and coeffs_next)) = '1' then
                rej_bounded_valid_coeffs_mux_count_vld <= 0;
            elsif mode_shift_reg(mode_shift_reg'left) = "101" or mode_shift_reg(mode_shift_reg'left) = "110" then
                if rej_next = '1' then
                    if bytes_vld = '1' then
                        -- if 4 coeffs are valid we will read them, so next cycle they will be invalidated
                        if rej_bounded_coeffs_vld = '1' then
                            rej_bounded_valid_coeffs_mux_count_vld <= rej_bounded_valid_coeffs_mux_count_vld - 4 + rej_bounded_coeffs_mux_count_vld;
                        else
                            rej_bounded_valid_coeffs_mux_count_vld <= rej_bounded_valid_coeffs_mux_count_vld + rej_bounded_coeffs_mux_count_vld;
                        end if;
                    -- if 4 coeffs are valid we will read them, so next cycle they will be invalidated
                    elsif rej_bounded_coeffs_vld = '1' then
                        rej_bounded_valid_coeffs_mux_count_vld <= rej_bounded_valid_coeffs_mux_count_vld - 4;
                    end if;
                end if;
            end if;
        end if;
    end process;

    with mode_shift_reg(mode_shift_reg'left - 1) select coeffs <=
        sample_cbd_coeffs when "001" | "010",
        rej_bounded_coeffs when "101" | "110",
        rej_ntt_valid_coeffs(95 downto 0) when others;

    with mode_shift_reg(mode_shift_reg'left - 1) select coeffs_vld <=
        sample_cbd_coeffs_vld when "001" | "010",
        rej_bounded_coeffs_vld when "101" | "110",
        rej_ntt_valid_coeffs_vld when others;

    rej_next <= not coeffs_vld or coeffs_next;
    coeffs_next <= not coeffs_vld_reg or m_axis_tready;

    coeffs_count_last <= '1' when coeffs_count = 63 or (mode_shift_reg(mode_shift_reg'left - 1)(2) = '0' and coeffs_count = 31) else '0';

    proc_out: process(clk) is
    begin
        if rising_edge(clk) then
            if coeffs_next = '1' then
                coeffs_reg <= coeffs;
                coeffs_count_last_reg <= coeffs_count_last and coeffs_vld;
            end if;

            if rst = '1' then
                coeffs_vld_reg <= '0';

                coeffs_count <= 0;
            else
                if coeffs_vld = '1' then
                    coeffs_vld_reg <= '1';
                elsif m_axis_tready = '1' then
                    coeffs_vld_reg <= '0';
                end if;

                if (coeffs_vld and coeffs_next) = '1' then
                    if coeffs_count_last = '1' then
                        coeffs_count <= 0;
                    else
                        coeffs_count <= coeffs_count + 1;
                    end if;
                end if;
            end if;
        end if;
    end process;

    process(clk) is
    begin
        if rising_edge(clk) then
            if reg_ready_m_axis_tvalid = '1' then
                mode_shift_reg(mode_shift_reg'left) <= reg_ready_m_axis_tuser;
            end if;

            mode_shift_reg(mode_shift_reg'left - 1 downto 0) <= mode_shift_reg(mode_shift_reg'left downto 1);
        end if;
    end process;
end;
