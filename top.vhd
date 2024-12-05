-- Copyright (C) 2024 Patrik Dobias <xdobia13@vut.cz>
-- Released for the non-commercial use only. For licensing, please contact <malina@vut.cz>

library ieee;
use ieee.std_logic_1164.all;
use ieee.numeric_std.all;

use work.params_pkg.all;
use work.reduce_pkg.all;

-- top component for CRYSTALS-Kyber and CRYSTALS-Dilithium
entity top is
generic (
    SIMULATION: boolean := false
);
port (
    clk: in std_logic;
    rst: in std_logic;

    s_axis_tdata: in std_logic_vector(63 downto 0);
    -- 10 downto 9 determines security level:
    -- - 00 - kyber 2, dilithium 2
    -- - 01 - kyber 3, dilithium 3
    -- - 10 - kyber 4, dilithium 5
    -- 8 downto 0 determines mode:
    -- - 000000001 - kyber - CPAPKE KeyGen
    -- - 000000010 - kyber - CPAPKE Enc
    -- - 000000100 - kyber - CPAPKE Dec
    -- - 000001000 - kyber - CCAKEM KeyGen
    -- - 000010000 - kyber - CCAKEM Enc
    -- - 000100000 - kyber - CCAKEM Dec
    -- - 001000000 - dilithium - KeyGen
    -- - 010000000 - dilithium - Sign
    -- - 100000000 - dilithium - Verify
    s_axis_tuser: in std_logic_vector(10 downto 0);
    s_axis_tlast: in std_logic;
    s_axis_tvalid: in std_logic;
    s_axis_tready: out std_logic;

    m_axis_tdata: out std_logic_vector(63 downto 0);
    m_axis_tvalid: out std_logic;
    m_axis_tready: in std_logic
);
end;

architecture behav of top is
    type slv_array_t is array (natural range <>) of std_logic_vector;

    -- constants
    constant BRAM_DELAY: natural := 2;

    -- signals for basic info
    signal param_k: natural range 2 to 8;
    signal param_l: natural range 4 to 7;
    signal is_dilithium: std_logic;

    -- signals for current mode
    signal mode: std_logic_vector(10 downto 0);
    signal mode_vld: std_logic;

    signal running: std_logic;

    -- LUTRAM storing all the needed values, that are not coefficients
    -- dilithium - key_gen:
    -- - 3 downto 0 => seed -> rho
    -- - 15 downto 8 => tr
    -- - 23 downto 16 => rho'
    -- - 27 downto 24 => K
    -- dilithium - sign:
    -- - 3 downto 0 => rho
    -- - 7 downto 4 => K
    -- - 15 downto 8 => tr -> mu
    -- - 23 downto 16 => rnd -> rho'
    -- - 31 downto 24 => c
    -- dilithium - verify:
    -- - 3 downto 0 => rho
    -- - 15 downto 8 => tr -> mu
    -- - 31 downto 24 => c
    -- kyber - pke_key_gen:
    -- - 3 downto 0 => seed -> rho
    -- - 19 downto 16 => sigma
    -- kyber - kem_key_gen (same as pke_key_gen +):
    -- - 11 downto 8 => H(pk)
    -- - 15 downto 12 => z
    -- kyber - pke_enc:
    -- - 3 downto 0 => rho
    -- - 19 downto 16 => r
    -- kyber - kem_enc (same as pke_enc +):
    -- - 11 downto 8 => H(pk)
    -- - 15 downto 12 => z -> K
    -- kyber - kem_dec (same as kem_enc +):
    -- - 31 downto 28 => K_ (shared key for implicit rejection)
    signal data: slv_array_t(31 downto 0)(63 downto 0) := (others => (others => '0'));
    -- accessing the data to infer LUTRAM correctly
    signal current_data: std_logic_vector(63 downto 0);
    signal data_input_loaded, rho_prime_vld, c_vld, tr_vld, mu_vld: std_logic;

    -- counters added to seeds that are hashed during polynomial samplings
    -- used for matrix sampling
    signal count_i, count_j: unsigned(7 downto 0);
    -- used for vectors sampling
    signal count_k: unsigned(15 downto 0);

    -- decode signals
    signal decode_s_axis_tdata: std_logic_vector(63 downto 0);
    signal decode_s_axis_tuser: std_logic_vector(3 downto 0);
    signal decode_s_axis_tvalid, decode_s_axis_tready: std_logic;

    signal decode_m_axis_tdata: std_logic_vector(95 downto 0);
    signal decode_m_axis_tuser: std_logic_vector(3 downto 0);
    signal decode_m_axis_tvalid, decode_m_axis_tready: std_logic;

    -- encode signals
    signal encode_s_axis_tdata: std_logic_vector(95 downto 0);
    signal encode_s_axis_tuser: std_logic_vector(3 downto 0);
    signal encode_s_axis_tvalid, encode_s_axis_tready: std_logic;

    signal encode_m_axis_tdata: std_logic_vector(63 downto 0);
    signal encode_m_axis_tvalid, encode_m_axis_tready: std_logic;

    -- compress signals
    signal compress_s_axis_tdata: std_logic_vector(95 downto 0);
    signal compress_s_axis_tuser: std_logic_vector(5 downto 0);
    signal compress_s_axis_tvalid, compress_s_axis_tready: std_logic;

    signal compress_m_axis_tdata, compress_m_axis_low_bits_tdata: std_logic_vector(95 downto 0);
    signal compress_m_axis_tuser: std_logic_vector(5 downto 0);
    signal compress_m_axis_tvalid, compress_m_axis_tready: std_logic;

    signal compress_mode_compress, compress_mode_decompress, compress_mode_high_bits, compress_mode_low_bits: std_logic;

    -- keccak signals
    signal keccak_read_all: std_logic;

    signal keccak_s_axis_tdata: std_logic_vector(63 downto 0);
    signal keccak_s_axis_tuser: std_logic_vector(1 downto 0);
    signal keccak_s_axis_tlast, keccak_s_axis_tvalid, keccak_s_axis_tready: std_logic;

    signal keccak_m_axis_tdata: std_logic_vector(63 downto 0);
    signal keccak_m_axis_tvalid, keccak_m_axis_tready: std_logic;

    signal keccak_first_transaction: std_logic;

    signal keccak_mode_in_with_mode: std_logic_vector(5 downto 0);
    signal keccak_mode_in, keccak_mode_out: std_logic_vector(3 downto 0);
    -- indicates what is used as input to `keccak`
    -- 001 - `data`
    -- 010 - `s_axis_tdata`
    -- 100 - `encode_m_axis_tdata`
    signal keccak_source: std_logic_vector(2 downto 0);
    -- indicates last valid data were fed to keccak, however it is not last transaction as the data need to be padded based on used hash function
    signal keccak_last_absorbing_iteration: std_logic;
    signal keccak_transactions_count, keccak_transactions_count_last: natural range 0 to 20;
    signal keccak_transactions_last: std_logic;

    -- helper counter for hashing of w1
    signal keccak_in_transactions_count, keccak_in_transactions_count_last: natural range 0 to 319;
    signal keccak_in_transactions_last: std_logic;

    -- keccak output is 1088b or 1344b and we read it in 64b transactions, so we need to keep track of it
    signal keccak_out_transactions_count, keccak_out_transactions_count_last: natural range 0 to 79;
    signal keccak_out_transactions_last: std_logic;

    signal keccak_out_transactions_count_last_y: natural range 70 to 79;

    -- sample signals
    signal sample_s_axis_tdata: std_logic_vector(63 downto 0);
    signal sample_s_axis_tuser: std_logic_vector(2 downto 0);
    signal sample_s_axis_tvalid, sample_s_axis_tready: std_logic;

    signal sample_m_axis_tdata: std_logic_vector(95 downto 0);
    signal sample_m_axis_tuser: std_logic_vector(2 downto 0);
    signal sample_m_axis_tlast, sample_m_axis_tvalid, sample_m_axis_tready: std_logic;

    -- sample_in_ball signals
    signal sample_in_ball_data_in: std_logic_vector(7 downto 0);
    signal sample_in_ball_data_in_vld: std_logic;

    signal sample_in_ball_m_axis_tdata: std_logic_vector(95 downto 0);
    signal sample_in_ball_m_axis_tvalid, sample_in_ball_m_axis_tready: std_logic;

    -- keccak is read out in 64b transactions, but we need only 8b transactions for `sample_in_ball`
    signal sample_in_ball_transactions_count: natural range 0 to 7;
    signal sample_in_ball_transactions_last: std_logic;

    -- poly multiplication signals
    signal poly_mul_start, poly_mul_rdy, poly_mul_vld: std_logic;
    signal poly_mul_mode: std_logic_vector(2 downto 0);
    signal poly_mul_coeffs_fifo_mode_in, poly_mul_coeffs_fifo_mode_out: std_logic_vector(2 downto 0);

    signal poly_mul_first_iteration, poly_mul_last_iteration: std_logic;

    signal poly_mul_inplace_coeffs: std_logic_vector(95 downto 0);
    signal poly_mul_inplace_op: std_logic_vector(1 downto 0);
    signal poly_mul_inplace_next: std_logic;

    signal poly_mul_coeffs_wea: std_logic;
    signal poly_mul_coeffs_dina, poly_mul_coeffs_doutb: std_logic_vector(95 downto 0);
    signal poly_mul_coeffs_addra, poly_mul_coeffs_addrb: std_logic_vector(6 downto 0);

    -- for dilithium last address is 63 and switching is done between 0-63 and 64-127
    -- for kyber last address is 31 and switching is done between 0-31 and 32-63
    signal poly_mul_coeffs_addra_last, poly_mul_coeffs_addra_mux: std_logic;
    signal poly_mul_coeffs_addrb_mux: std_logic;

    -- polynomial multiplication might read from `bram0` or `bram1` this is indicated by following muxes
    signal poly_mul_bram_mux, poly_mul_bram_mux_reg: std_logic;
    signal poly_mul_read_bram_mux: std_logic;
    -- to compensate BRAM_DELAY
    signal poly_mul_coeffs_read_bram_mux_shift_reg: std_logic_vector(BRAM_DELAY - 1 downto 0);

    signal poly_mul_validity_check_mode: std_logic_vector(1 downto 0);

    signal poly_mul_first_bram_only: std_logic;
    signal poly_mul_repeat_read: std_logic;

    signal poly_mul_offset_we: std_logic_vector(1 downto 0);
    signal poly_mul_addra_offset0, poly_mul_addra_offset1: std_logic_vector(5 downto 0);
    signal poly_mul_addrb_offset0, poly_mul_addrb_offset1: std_logic_vector(5 downto 0);

    signal poly_mul_running, poly_mul_half, poly_mul_half_finished, poly_mul_finished: std_logic;

    -- bram 0 signals
    signal bram0_wea, bram0_reb: std_logic;
    signal bram0_dina, bram0_doutb: std_logic_vector(95 downto 0);
    signal bram0_addra, bram0_addra_reg, bram0_addrb: std_logic_vector(8 downto 0);

    -- for dilithium last address is 63, for kyber last address is 31
    signal bram0_addra_reg_last, bram0_addrb_last: std_logic;

    signal bram0_addrb_offset: std_logic_vector(3 downto 0);

    -- dilithium uses every second bit as it needs double the memory for storing coefficients
    signal bram0_polys_vld: std_logic_vector(15 downto 0);
    signal bram0_can_write: std_logic;

    -- bram 1 signals
    signal bram1_wea, bram1_reb: std_logic;
    signal bram1_dina, bram1_doutb: std_logic_vector(95 downto 0);
    signal bram1_addra, bram1_addrb: std_logic_vector(11 downto 0);
    signal bram1_addrb_reg: std_logic_vector(5 downto 0);

    -- for dilithium last address is 63, for kyber last address is 31
    signal bram1_addra_reg_kyber_last, bram1_addrb_reg_last, bram1_addrb_reg_second_to_last: std_logic;

    -- used when we want to store same values in `bram1` as in `bram0` (e.g. s1, s2 during dilithium key_gen)
    signal bram1_copy_bram0: std_logic;
    -- used when we want to store values in `bram1` instead of `bram0` (e.g. s during kyber pke_dec)
    signal bram1_take_bram0: std_logic;
    -- used during decapsulation for message storing
    signal bram1_store_dec_m, bram1_stored_dec_m: std_logic;
    signal bram1_addra_reg: std_logic_vector(11 downto 0);

    signal bram1_mode: std_logic_vector(3 downto 0);
    signal bram1_addrb_offset: std_logic_vector(5 downto 0);

    signal bram1_reading_vld: std_logic;

     -- to compensate BRAM_DELAY
    signal bram1_mode_shift_reg: slv_array_t(BRAM_DELAY - 1 downto 0)(3 downto 0);


    -- small fifo for coefficients
    -- 99 downto 96 determines type of coeffs stored in fifo
    -- 0000 - inplace addition/subtraction
    -- 0001 - w high bits
    -- 0010 - w - cs2 low bits
    -- 0011 - z compression
    signal coeffs_fifo_din, coeffs_fifo_dout: std_logic_vector(99 downto 0);
    signal coeffs_fifo_din_vld, coeffs_fifo_dout_vld, coeffs_fifo_dout_rdy: std_logic;

    -- to compensate BRAM_DELAY
    signal coeffs_fifo_vld: std_logic_vector(BRAM_DELAY - 1 downto 0);

    -- cipher fifo for ciphertext checks
    signal cipher_fifo_din, cipher_fifo_dout: std_logic_vector(63 downto 0);
    signal cipher_fifo_din_vld, cipher_fifo_dout_vld, cipher_fifo_dout_rdy: std_logic;

    signal cipher_eq, cipher_eq_vld: std_logic;

    signal cipher_transactions_count, cipher_transactions_count_last: natural range 0 to 195;
    signal cipher_transactions_last: std_logic;

    -- validity check signals
    signal validity_check_mode: std_logic_vector(3 downto 0);
    signal validity_check_coeffs: std_logic_vector(95 downto 0);
    signal validity_check_coeffs_vld, validity_check_valid, validity_check_valid_vld: std_logic;

    -- make_hint signals
    signal make_hint_coeffs_high_bits: std_logic_vector(23 downto 0);
    signal make_hint_coeffs: std_logic_vector(95 downto 0);
    signal make_hint_coeffs_vld: std_logic;

    signal make_hint_m_axis_tdata: std_logic_vector(63 downto 0);
    signal make_hint_m_axis_tuser, make_hint_m_axis_tvalid, make_hint_m_axis_tready: std_logic;

    -- use_hint signals
    signal use_hint_s_axis_tdata: std_logic_vector(63 downto 0);
    signal use_hint_s_axis_tvalid, use_hint_s_axis_tready: std_logic;

    signal use_hint_m_axis_tdata: std_logic_vector(23 downto 0);
    signal use_hint_m_axis_tvalid, use_hint_m_axis_tready: std_logic;

    signal use_hint_hints_invalid: std_logic;

    signal sig_invalid: std_logic;

    -- verify signals
    signal verified, verified_vld: std_logic;

    -- input transactions signals
    signal in_mode: std_logic_vector(3 downto 0);
    signal in_decode_mode: std_logic_vector(3 downto 0);
    signal in_transaction_offset: natural range 0 to 31;

    signal in_rdy, in_next_mode: std_logic;

    -- output transactions signals
    signal outputing: std_logic;
    signal out_mode: std_logic_vector(2 downto 0);
    signal out_transaction_last: std_logic;
    signal out_transaction_offset_tmp, out_transaction_offset: natural range 0 to 31;
    signal out_pk: std_logic;

    signal out_data: std_logic_vector(63 downto 0);
    signal out_vld: std_logic;

    -- signals for debugging during simulation
    signal DATA_DEBUG: std_logic_vector(2047 downto 0);
begin
    s_axis_tready <= in_rdy and running;

    m_axis_tdata <= (0 => verified, 63 downto 1 => '0') when mode(8) = '1' else out_data;
    m_axis_tvalid <= verified_vld when mode(8) = '1' else out_vld;

    -- determine if we do dilithium or kyber and correct security parameters
    proc_param: process(clk) is
    begin
        if rising_edge(clk) then
            if mode_vld = '0' then
                if s_axis_tuser(8 downto 6) /= "000" then
                    is_dilithium <= '1';
                    param_k <= dilithium_k(s_axis_tuser(10 downto 9));
                    param_l <= dilithium_l(s_axis_tuser(10 downto 9));
                else
                    is_dilithium <= '0';
                    param_k <= kyber_k(s_axis_tuser(10 downto 9));
                end if;
            end if;
        end if;
    end process;

    -- Store current mode of this component

    proc_mode: process(clk) is
    begin
        if rising_edge(clk) then
            if mode_vld = '0' then
                mode <= s_axis_tuser;
            end if;

            if rst = '1' then
                mode_vld <= '0';
                running <= '0';
            else
                if s_axis_tvalid = '1' then
                    mode_vld <= '1';
                end if;

                running <= mode_vld;

                if ((out_vld or verified_vld) and m_axis_tready and out_transaction_last) = '1' then
                    mode_vld <= '0';
                    running <= '0';
                end if;
            end if;
        end if;
    end process;


    -- Decode initial data, that are not part of coefficients
    -- Also hold additional data, like hashing seeds, that are computed later

    proc_data: process(clk) is
        variable addr: natural range 0 to 31;
    begin
        if rising_edge(clk) then
            if running = '0' then
                data_input_loaded <= '0';
            elsif in_mode(0) = '0' then
                data_input_loaded <= '1';
            end if;

            if in_mode(0) = '1' then
                addr := in_transaction_offset;
            elsif keccak_m_axis_tvalid = '1' then
                case keccak_mode_out is
                    -- rho, rho_prime, K for dilithium key_gen
                    when "0000" =>
                        if keccak_out_transactions_count < 4 then
                            addr := keccak_out_transactions_count;
                        else
                            addr := 12 + keccak_out_transactions_count;
                        end if;
                    -- tr for dilithium key_gen
                    when "0011" => addr := 8 + keccak_out_transactions_count;
                    -- mu for dilithium sign
                    when "0100" => addr := 8 + keccak_out_transactions_count;
                    -- rho_prime for ExpandA and ExpandMask for dilithium sign
                    when "0101" => addr := 16 + keccak_out_transactions_count;
                    -- c - part of signature
                    when "0111" => addr := 24 + keccak_out_transactions_count;
                    -- rho, sigma for kyber pke_key_gen
                    when "1001" =>
                        if keccak_out_transactions_count < 4 then
                            addr := keccak_out_transactions_count;
                        else
                            addr := 12 + keccak_out_transactions_count;
                        end if;
                    -- H(pk)
                    when "1010" => addr := 8 + keccak_out_transactions_count;
                    -- G(m || H(pk))
                    when "1100" => addr := 12 + keccak_out_transactions_count;
                    -- J(z || c)
                    when "1101" => addr := 28 + keccak_out_transactions_count;
                    when others =>
                end case;
            end if;

            -- this is just for simulation testing, won't infer RAM with this
            if SIMULATION then
                if running = '0' then
                    data <= (others => (others => '0'));
                end if;
            end if;

            if in_mode(0) = '1' then
                data(addr) <= s_axis_tdata;
            elsif keccak_m_axis_tvalid = '1' and (keccak_mode_out = "0000" or keccak_mode_out = "0011" or keccak_mode_out = "0100" or keccak_mode_out = "0101" or keccak_mode_out = "0111" or keccak_mode_out = "1001" or keccak_mode_out = "1010" or keccak_mode_out = "1100" or keccak_mode_out = "1101") then
                data(addr) <= keccak_m_axis_tdata;
            end if;

            if running = '0' then
                rho_prime_vld <= '0';
                c_vld <= '0';
                tr_vld <= '0';
                mu_vld <= '0';
            else
                if (keccak_m_axis_tvalid and keccak_out_transactions_last) = '1' and (keccak_mode_out = "0000" or keccak_mode_out = "0101" or keccak_mode_out = "1001" or keccak_mode_out = "1100") then
                    rho_prime_vld <= '1';
                end if;

                if (s_axis_tvalid and mode(1)) = '1' and in_transaction_offset = 19 then
                    rho_prime_vld <= '1';
                end if;

                if (s_axis_tvalid and mode(5)) = '1' and in_transaction_offset = 15 then
                    c_vld <= '1';
                end if;

                if (keccak_m_axis_tvalid and keccak_out_transactions_last) = '1' and (keccak_mode_out = "0011" or keccak_mode_out = "0111" or keccak_mode_out = "1010") then
                    c_vld <= '1';
                end if;

                if (keccak_m_axis_tvalid and keccak_out_transactions_last) = '1' and (keccak_mode_out = "0011") then
                    tr_vld <= '1';
                end if;

                if (mode(7) and data_input_loaded) = '1' then
                    tr_vld <= '1';
                end if;

                if (keccak_m_axis_tvalid and keccak_out_transactions_last) = '1' and (keccak_mode_out = "0100") then
                    mu_vld <= '1';
                end if;

                if sig_invalid = '1' then
                    c_vld <= '0';
                end if;
            end if;
        end if;
    end process;

    proc_data_read: process(all) is
        variable addr: natural range 0 to 31;
    begin
        if (outputing and out_mode(0)) = '1' then
            addr := out_transaction_offset;
        elsif keccak_m_axis_tvalid = '1' and keccak_mode_out = "0111" then
            addr := 24 + keccak_out_transactions_count;
        else
            -- see `proc_keccak_in` for explanation what hashes are computed
            case keccak_mode_in is
                when "0001" | "0110" | "1011" => addr := 16 + keccak_transactions_count;
                when "0100" | "0111" => addr := 8 + keccak_transactions_count;
                when "0101" => if keccak_transactions_count < 4 then addr := 4 + keccak_transactions_count; elsif keccak_transactions_count < 8 then addr := 12 + keccak_transactions_count; else addr := keccak_transactions_count; end if;
                when "1000" => if keccak_transactions_count < 8 then addr := 24 + keccak_transactions_count; end if;
                when "1010" => addr := out_transaction_offset;
                when "1100" => addr := 4 + keccak_transactions_count;
                when "1101" => addr := 12 + keccak_transactions_count;
                when others => addr := keccak_transactions_count;
            end case;
        end if;

        current_data <= data(addr);
    end process;

    -- Increment counters for hashing during polynomial samplings

    proc_counters: process(clk) is
    begin
        if rising_edge(clk) then
            if running = '0' then
                count_i <= x"00";
                count_j <= x"00";
                count_k <= x"0000";
            else
                -- reset counter for ExpandA
                if sig_invalid = '1' then
                    count_i <= x"00";
                end if;

                if keccak_read_all = '1' then
                    case keccak_mode_out is
                        -- increment counters during ExpandMask and ExpandS
                        when "0001" | "0110" | "1011" => count_k <= count_k + 1;
                        -- increment counters during ExpandA
                        when "0010" =>
                            if count_j = param_k - 1 then
                                count_j <= x"00";

                                count_i <= count_i + 1;
                            else
                                count_j <= count_j + 1;
                            end if;
                        when others =>
                    end case;
                end if;
            end if;
        end if;
    end process;

    -- Coefficients decoding
    -- coefficients are decoded from input, only during ExpandMask operation they are decoded from keccak output

    decode: entity work.decode
    port map (
        clk => clk,
        rst => not running,

        s_axis_tdata => decode_s_axis_tdata,
        s_axis_tuser => decode_s_axis_tuser,
        s_axis_tvalid => decode_s_axis_tvalid,
        s_axis_tready => decode_s_axis_tready,

        m_axis_tdata => decode_m_axis_tdata,
        m_axis_tuser => decode_m_axis_tuser,
        m_axis_tvalid => decode_m_axis_tvalid,
        m_axis_tready => decode_m_axis_tready
    );

    decode_s_axis_tdata <= keccak_m_axis_tdata when keccak_mode_out = "0110" else s_axis_tdata;
    decode_s_axis_tuser <= "1001" when keccak_mode_out = "0110" and mode(10 downto 9) = "00" else
        "1000" when keccak_mode_out = "0110" else
        in_decode_mode;
    decode_s_axis_tvalid <= keccak_m_axis_tvalid when keccak_mode_out = "0110" else
        -- make sure it is correctly synchronized, when input is also fed to keccak
        (in_mode(1) and s_axis_tvalid) and (not in_mode(2) or (keccak_s_axis_tready and not keccak_last_absorbing_iteration and keccak_source(1)));

    -- coefficients are always passed to `compress` component
    decode_m_axis_tready <= compress_s_axis_tready;

    -- Coefficients encoding

    encode: entity work.encode
    port map (
        clk => clk,
        rst => not running or sig_invalid,

        s_axis_tdata => encode_s_axis_tdata,
        s_axis_tuser => encode_s_axis_tuser,
        s_axis_tvalid => encode_s_axis_tvalid,
        s_axis_tready => encode_s_axis_tready,

        m_axis_tdata => encode_m_axis_tdata,
        m_axis_tvalid => encode_m_axis_tvalid,
        m_axis_tready => encode_m_axis_tready
    );

    -- encoded are:
    -- w1 recovered from `use_hint`
    -- t1 high bits for dilithium's key_gen
    -- all compressed coefficients
    proc_encode: process(all) is
    begin
        if use_hint_m_axis_tvalid = '1' then
            for i in 0 to 3 loop
                encode_s_axis_tdata(23 + 24 * i downto 24 * i) <= (23 downto 6 => '0') & use_hint_m_axis_tdata(5 + 6 * i downto 6 * i);
            end loop;

            encode_s_axis_tuser <= "1100" when mode(10 downto 9) = "00" else "1101";
            encode_s_axis_tvalid <= '1';
        else
            for i in 0 to 3 loop
                encode_s_axis_tdata(23 + 24 * i downto 24 * i) <= compress_m_axis_tdata(23 + 24 * i downto 24 * i);
            end loop;

            encode_s_axis_tuser <= compress_m_axis_tuser(3 downto 0);
            encode_s_axis_tvalid <= compress_m_axis_tvalid and (compress_mode_compress or (compress_mode_high_bits and not mode(8)));
        end if;
    end process;

    encode_m_axis_tready <= m_axis_tready and keccak_s_axis_tready and not keccak_last_absorbing_iteration and not keccak_source(0) when out_mode(1) = '1' and (keccak_mode_in = "0011" or keccak_mode_in = "1010") else
        keccak_s_axis_tready and not keccak_last_absorbing_iteration and not keccak_source(0) when keccak_mode_in = "0111" or keccak_mode_in = "1100" else
        m_axis_tready when out_mode(1) = '1' else
        mode(5);

    -- Coefficients compression/decompression

    compress: entity work.compress
    port map (
        clk => clk,
        rst => not running,

        s_axis_tdata => compress_s_axis_tdata,
        s_axis_tuser => compress_s_axis_tuser,
        s_axis_tvalid => compress_s_axis_tvalid,
        s_axis_tready => compress_s_axis_tready,

        m_axis_tdata => compress_m_axis_tdata,
        m_axis_low_bits_tdata => compress_m_axis_low_bits_tdata,
        m_axis_tuser => compress_m_axis_tuser,
        m_axis_tvalid => compress_m_axis_tvalid,
        m_axis_tready => compress_m_axis_tready
    );

    proc_compress_in: process(all) is
    begin
        compress_s_axis_tdata <= (others => '0');
        compress_s_axis_tuser <= (others => '0');
        compress_s_axis_tvalid <= '0';

        -- if there are coefficients for decompression process them
        if decode_m_axis_tvalid = '1' then
            compress_s_axis_tdata <= decode_m_axis_tdata;
            compress_s_axis_tuser <= "01" & decode_m_axis_tuser(3 downto 0);
            compress_s_axis_tvalid <= decode_m_axis_tvalid;
        -- compute low bits of w - cs2
        elsif poly_mul_validity_check_mode = "10" and mode(7) = '1' then
            compress_s_axis_tdata <= poly_mul_coeffs_dina;
            compress_s_axis_tuser <= std_logic_vector_for_sec_level(mode(10 downto 9), "111100", "111101", "111101");
            compress_s_axis_tvalid <= poly_mul_coeffs_wea and poly_mul_last_iteration;
        -- compute low bits of w - cs2
        elsif bram1_mode_shift_reg(0) = "0101" then
            compress_s_axis_tdata <= bram1_doutb;
            compress_s_axis_tuser <= std_logic_vector_for_sec_level(mode(10 downto 9), "111100", "111101", "111101");
            compress_s_axis_tvalid <= '1';
        -- power2round of t
        elsif coeffs_fifo_dout_vld = '1' then
            compress_s_axis_tdata <= coeffs_fifo_dout(95 downto 0);

            case coeffs_fifo_dout(99 downto 96) is
                -- power2round of t
                when "0000" =>
                    compress_s_axis_tuser <= "101011";
                    compress_s_axis_tvalid <= '1';
                -- compress s1, s2 when outputing
                when "0001" =>
                    compress_s_axis_tuser <= std_logic_vector_for_sec_level(mode(10 downto 9), "001111", "001110", "001111");
                    compress_s_axis_tvalid <= '1';
                -- compress t0 when outputing
                when "0010" =>
                    compress_s_axis_tuser <= "001010";
                    compress_s_axis_tvalid <= '1';
                -- compute high bits of w
                when "0011" | "0111" =>
                    compress_s_axis_tuser <= std_logic_vector_for_sec_level(mode(10 downto 9), "101100", "101101", "101101");
                    compress_s_axis_tvalid <= '1';
                -- compress z when outputing
                when "0110" =>
                    compress_s_axis_tuser <= std_logic_vector_for_sec_level(mode(10 downto 9), "001001", "001000", "001000");
                    compress_s_axis_tvalid <= '1';
                -- compress t, s when outputing
                when "1000" | "1001" =>
                    compress_s_axis_tuser <= "000000";
                    compress_s_axis_tvalid <= '1';
                -- compress m when outputing
                when "1010" =>
                    compress_s_axis_tuser <= "000101";
                    compress_s_axis_tvalid <= '1';
                -- compress u when outputing
                when "1011" =>
                    compress_s_axis_tuser <= std_logic_vector_for_sec_level(mode(10 downto 9), "000010", "000010", "000001");
                    compress_s_axis_tvalid <= '1';
                -- compress v when outputing
                when "1101" =>
                    compress_s_axis_tuser <= std_logic_vector_for_sec_level(mode(10 downto 9), "000100", "000100", "000011");
                    compress_s_axis_tvalid <= '1';
                when others =>
            end case;
        end if;
    end process;

    compress_m_axis_tready <= not poly_mul_finished or coeffs_fifo_dout_vld when compress_mode_low_bits = '1' else
        use_hint_s_axis_tready when compress_mode_high_bits = '1' and mode(8) = '1' else
        bram0_can_write when compress_mode_decompress = '1' else
        encode_s_axis_tready;

    compress_mode_compress <= '1' when compress_m_axis_tuser(5 downto 4) = "00" else '0';
    compress_mode_decompress <= '1' when compress_m_axis_tuser(5 downto 4) = "01" else '0';
    compress_mode_high_bits <= '1' when compress_m_axis_tuser(5 downto 4) = "10" else '0';
    compress_mode_low_bits <= '1' when compress_m_axis_tuser(5 downto 4) = "11" else '0';

    -- Keccak

    keccak: entity work.keccak
    port map (
        clk => clk,
        rst => not running or sig_invalid,

        read_all => keccak_read_all,

        s_axis_tdata => keccak_s_axis_tdata,
        s_axis_tuser => keccak_s_axis_tuser,
        s_axis_tlast => keccak_s_axis_tlast,
        s_axis_tvalid => keccak_s_axis_tvalid,
        s_axis_tready => keccak_s_axis_tready,

        m_axis_tdata => keccak_m_axis_tdata,
        m_axis_tvalid => keccak_m_axis_tvalid,
        m_axis_tready => keccak_m_axis_tready
    );

    with keccak_mode_out select keccak_read_all <=
        sample_m_axis_tlast when "0010" |  "0001" | "1011",
        decode_s_axis_tvalid and decode_s_axis_tready and keccak_out_transactions_last when "0110",
        sample_in_ball_m_axis_tvalid when "1000",
        keccak_m_axis_tvalid and keccak_out_transactions_last when others;

    with keccak_mode_out select keccak_m_axis_tready <=
        sample_s_axis_tready when "0010" | "0001" | "1011",
        decode_s_axis_tready when "0110",
        sample_in_ball_transactions_last when "1000",
        not in_mode(0) when others;

    keccak_state_machine: entity work.keccak_state_machine
    port map (
        clk => clk,
        rst => not running,

        mode => mode,

        param_k => param_k,
        param_l => param_l,

        sig_invalid => sig_invalid,

        next_mode => keccak_s_axis_tvalid and keccak_s_axis_tready and keccak_s_axis_tlast,

        keccak_mode => keccak_mode_in
    );

    proc_keccak_in: process(all) is
    begin
        keccak_s_axis_tdata <= (others => '0');
        keccak_s_axis_tlast <= keccak_last_absorbing_iteration;
        keccak_s_axis_tvalid <= '0';

        if keccak_last_absorbing_iteration = '1' then
            keccak_s_axis_tdata(63 downto 0) <= (others => '0');
            keccak_s_axis_tdata(7 downto 0) <= x"06" when keccak_mode_in = "1010" or keccak_mode_in = "1100" else x"1f";
            keccak_s_axis_tvalid <= '1';
        else
            case keccak_source is
                when "010" =>
                    keccak_s_axis_tdata <= s_axis_tdata;
                    keccak_s_axis_tvalid <= s_axis_tvalid and in_mode(2) and (not in_mode(1) or decode_s_axis_tready);
                when "100" =>
                    keccak_s_axis_tdata <= encode_m_axis_tdata;
                    keccak_s_axis_tvalid <= encode_m_axis_tvalid and (not out_mode(1) or m_axis_tready);
                when others =>
            end case;

            case keccak_mode_in is
                -- (rho, rho_prime, K) = H(seed)
                when "0000" =>
                    if keccak_transactions_count < 4 then
                        keccak_s_axis_tdata <= current_data;
                    elsif keccak_transactions_count = 4 then
                        keccak_s_axis_tdata <= (63 downto 24 => '0') & x"1f" & std_logic_vector(to_unsigned(param_l, 8)) & std_logic_vector(to_unsigned(param_k, 8));
                        keccak_s_axis_tlast <= '1';
                    end if;

                    keccak_s_axis_tvalid <= data_input_loaded;
                -- H(rho' || n) - ExpandS, ExpandMask, PRF
                when "0001" | "0110" | "1011" =>
                    if is_dilithium = '1' then
                        if keccak_transactions_count < 8 then
                            keccak_s_axis_tdata <= current_data;
                        elsif keccak_transactions_count = 8 then
                            keccak_s_axis_tdata <= (63 downto 24 => '0') & x"1f" & std_logic_vector(count_k);
                            keccak_s_axis_tlast <= '1';
                        end if;
                    else
                        if keccak_transactions_count < 4 then
                            keccak_s_axis_tdata <= current_data;
                        elsif keccak_transactions_count = 4 then
                            keccak_s_axis_tdata <= (63 downto 16 => '0') & x"1f" & std_logic_vector(count_k(7 downto 0));
                            keccak_s_axis_tlast <= '1';
                        end if;
                    end if;

                    keccak_s_axis_tvalid <= rho_prime_vld;
                -- H_128(rho || n) - ExpandA, XOF
                when "0010" =>
                    if keccak_transactions_count < 4 then
                        keccak_s_axis_tdata <= current_data;
                    elsif keccak_transactions_count = 4 then
                        keccak_s_axis_tdata <= (63 downto 24 => '0') & x"1f" & std_logic_vector(count_j) & std_logic_vector(count_i);
                        keccak_s_axis_tlast <= '1';
                    end if;

                    keccak_s_axis_tvalid <= data_input_loaded;
                -- tr = H(pk)
                when "0011" =>
                    if keccak_source(0) = '1' then
                        keccak_s_axis_tdata <= current_data;
                        keccak_s_axis_tvalid <= data_input_loaded;
                    end if;
                -- mu = H(tr || msg)
                when "0100" =>
                    if keccak_source(0) = '1' then
                        keccak_s_axis_tdata <= current_data;
                        keccak_s_axis_tvalid <= tr_vld;
                    else
                        keccak_s_axis_tlast <= s_axis_tlast;
                    end if;
                -- rho_prime = H(K || rnd || mu)
                when "0101" =>
                    if keccak_transactions_count < 4 then
                        keccak_s_axis_tdata <= current_data;
                    elsif keccak_transactions_count < 8 then
                        keccak_s_axis_tdata <= current_data;
                    else
                        keccak_s_axis_tdata <= current_data;
                    end if;

                    keccak_s_axis_tvalid <= data_input_loaded;
                -- c = H(mu || w1)
                when "0111" =>
                    if keccak_source(0) = '1' then
                        keccak_s_axis_tdata <= current_data;
                        keccak_s_axis_tvalid <= data_input_loaded;
                    end if;
                -- H(c1) - SampleInBall
                when "1000" =>
                    if keccak_transactions_count < dilithium_c_transactions(mode(10 downto 9)) then
                        keccak_s_axis_tdata <= current_data;
                    elsif keccak_transactions_count = dilithium_c_transactions(mode(10 downto 9)) then
                        keccak_s_axis_tdata <= (63 downto 8 => '0') & x"1f";
                        keccak_s_axis_tlast <= '1';
                    end if;

                    keccak_s_axis_tvalid <= c_vld;
                -- (rho, sigma) = G(seed)
                when "1001" =>
                    if keccak_transactions_count < 4 then
                        keccak_s_axis_tdata <= current_data;
                    elsif keccak_transactions_count = 4 then
                        keccak_s_axis_tdata <= (63 downto 16 => '0') & x"06" & std_logic_vector(to_unsigned(param_k, 8));
                        keccak_s_axis_tlast <= '1';
                    end if;

                    keccak_s_axis_tvalid <= data_input_loaded;
                -- H(pk)
                when "1010" =>
                    if mode(4) = '1' then
                        keccak_s_axis_tvalid <= s_axis_tvalid and (decode_s_axis_tready or not in_mode(1)) and keccak_source(1);
                    else
                        keccak_s_axis_tdata <= current_data when out_mode(0) = '1' else encode_m_axis_tdata;
                        keccak_s_axis_tvalid <= outputing and m_axis_tready when out_mode(0) = '1' else encode_m_axis_tvalid and m_axis_tready;
                    end if;
                -- G(m || H(pk))
                when "1100" =>
                    if keccak_transactions_count < 4 then
                        if mode(5) = '0' then
                            keccak_s_axis_tvalid <= s_axis_tvalid and (decode_s_axis_tready or not in_mode(1)) and keccak_source(1);
                        end if;
                    else
                        keccak_s_axis_tdata <= current_data;
                        keccak_s_axis_tvalid <= c_vld;
                    end if;
                -- J(z || c)
                when "1101" =>
                    if keccak_source(0) = '1' then
                        keccak_s_axis_tdata <= current_data;
                        keccak_s_axis_tvalid <= c_vld;
                    elsif keccak_source(1) = '1' then
                        keccak_s_axis_tvalid <= s_axis_tvalid and decode_s_axis_tready;
                    end if;
                when others =>
            end case;
        end if;
    end process;

    with keccak_mode_in select keccak_s_axis_tuser <=
        "00" when "0010",
        "11" when "1001" | "1100",
        "10" when "1010",
        "01" when others;

    -- SHAKE-128 uses r = 1344 => 21 64b transactions
    -- SHAKE-256 uses r = 1088 => 17 64b transactions
    -- SHA3-256 uses r = 1088 => 17 64b transactions
    -- SHA3-512 uses r = 576 => 9 64b transactions
    with keccak_mode_in select keccak_transactions_count_last <=
        20 when "0010",
        8 when "1001" | "1100",
        16 when others;

    keccak_transactions_last <= '1' when keccak_transactions_count = keccak_transactions_count_last else keccak_s_axis_tlast;

    proc_keccak_source: process(clk) is
    begin
        if rising_edge(clk) then
            if keccak_first_transaction = '1' then
                case keccak_mode_in is
                    when "1010" => keccak_source <= "010" when mode(4) = '1' else "100";
                    when "1100" => keccak_source <= "100" when mode(5) = '1' else "010";
                    when "1111" => keccak_source <= "000";
                    when others => keccak_source <= "001";
                end case;
            elsif (keccak_s_axis_tvalid and keccak_s_axis_tready) = '1' then
                if keccak_transactions_count = 7 then
                    case keccak_mode_in is
                        when "0100" => keccak_source <= "010";
                        when "0111" => keccak_source <= "100";
                        when others =>
                    end case;
                end if;

                if keccak_transactions_count = 3 then
                    case keccak_mode_in is
                        when "0011" => keccak_source <= "010" when mode(8) = '1' else "100";
                        when "1100" => keccak_source <= "001";
                        when "1101" => keccak_source <= "010";
                        when others =>
                    end case;
                end if;
            end if;
        end if;
    end process;

    proc_keccak: process(clk) is
    begin
        if rising_edge(clk) then
            if (not running or sig_invalid) = '1' then
                keccak_mode_out <= (others => '0');

                keccak_first_transaction <= '1';
                keccak_last_absorbing_iteration <= '0';

                keccak_transactions_count <= 0;
            else
                if (keccak_s_axis_tvalid and keccak_s_axis_tready) = '1' then
                    keccak_first_transaction <= keccak_s_axis_tlast;

                    if keccak_transactions_last = '1' then
                        keccak_last_absorbing_iteration <= '0';

                        keccak_transactions_count <= 0;
                    else
                        keccak_transactions_count <= keccak_transactions_count + 1;
                    end if;
                end if;

                if (keccak_s_axis_tlast and keccak_s_axis_tvalid) = '1' then
                    keccak_mode_out <= keccak_mode_in;
                end if;

                if keccak_last_absorbing_iteration = '0' then
                    case keccak_mode_in is
                        -- mu = H(tr || msg)
                        -- padding is already added to message
                        when "0100" => keccak_last_absorbing_iteration <= '0';
                        -- tr = H(pk)
                        when "0011" => keccak_last_absorbing_iteration <= keccak_in_transactions_last and keccak_s_axis_tvalid and keccak_s_axis_tready;
                        -- c = H(mu || w1)
                        when "0111" => keccak_last_absorbing_iteration <= keccak_in_transactions_last and keccak_s_axis_tvalid and keccak_s_axis_tready;
                        -- H(pk)
                        when "1010" => keccak_last_absorbing_iteration <= keccak_in_transactions_last and keccak_s_axis_tvalid and keccak_s_axis_tready;
                        -- J(z || c)
                        when "1101" => keccak_last_absorbing_iteration <= keccak_in_transactions_last and keccak_s_axis_tvalid and keccak_s_axis_tready;
                        when others =>
                            if keccak_transactions_count = keccak_transactions_count_last - 1 then
                                keccak_last_absorbing_iteration <= '1';
                            end if;
                    end case;
                end if;
            end if;
        end if;
    end process;

    keccak_mode_in_with_mode <= mode(10 downto 9) & keccak_mode_in;

    with keccak_mode_in_with_mode select keccak_in_transactions_count_last <=
        40 * param_k - 1 when "000011" | "010011" | "100011",
        95 when "000111" | "010111",
        127 when "100111",
        -- t + rho
        48 * param_k + 4 - 1 when "001010" | "011010" | "101010",
        -- z + c
        95 when "001101",
        135 when "011101",
        195 when "101101",
        0 when others;

    keccak_out_transactions_count_last_y <= 71 when mode(10 downto 9) = "00" else 79;

    -- SHAKE-128 uses r = 1344 => 21 64b transactions
    -- SHAKE-256 uses r = 1088 => 17 64b transactions
    with keccak_mode_out select keccak_out_transactions_count_last <=
        -- rho (4), rho_prime (8), K (4)
        15 when "0000",
        -- tr | mu | rho_prime | rho, sigma | G(m || H(pk))
        7 when "0011" | "0100" | "0101" | "1001" | "1100",
        -- c
        dilithium_c_transactions(mode(10 downto 9)) - 1 when "0111",
        -- H(pk) | K_
        3 when "1010" | "1101",
        20 when "0010",
        -- ExpandMask
        keccak_out_transactions_count_last_y when "0110",
        16 when others;

    keccak_in_transactions_last <= '1' when keccak_in_transactions_count = keccak_in_transactions_count_last else '0';
    keccak_out_transactions_last <= '1' when keccak_out_transactions_count = keccak_out_transactions_count_last else '0';

    proc_keccak_transactions: process(clk) is
    begin
        if rising_edge(clk) then
            if (not running or sig_invalid) = '1' then
                keccak_in_transactions_count <= 0;
                keccak_out_transactions_count <= 0;
            else
                if (keccak_s_axis_tvalid and keccak_s_axis_tready and (not keccak_source(0) or mode(4))) = '1' then
                    if (keccak_in_transactions_last or keccak_s_axis_tlast) = '1' then
                        keccak_in_transactions_count <= 0;
                    else
                        keccak_in_transactions_count <= keccak_in_transactions_count + 1;
                    end if;
                end if;

                if keccak_read_all = '1' then
                    keccak_out_transactions_count <= 0;
                else
                    if (keccak_m_axis_tvalid and keccak_m_axis_tready) = '1' then
                        if keccak_out_transactions_last = '1' then
                            keccak_out_transactions_count <= 0;
                        else
                            keccak_out_transactions_count <= keccak_out_transactions_count + 1;
                        end if;
                    end if;
                end if;
            end if;
        end if;
    end process;

    -- Coefficients sampling

    sample: entity work.sample
    port map (
        clk => clk,
        rst => not running,

        s_axis_tdata => sample_s_axis_tdata,
        s_axis_tuser => sample_s_axis_tuser,
        s_axis_tvalid => sample_s_axis_tvalid,
        s_axis_tready => sample_s_axis_tready,

        m_axis_tdata => sample_m_axis_tdata,
        m_axis_tuser => sample_m_axis_tuser,
        m_axis_tlast => sample_m_axis_tlast,
        m_axis_tvalid => sample_m_axis_tvalid,
        m_axis_tready => sample_m_axis_tready
    );

    sample_s_axis_tdata <= keccak_m_axis_tdata;

    proc_sample_in: process(all) is
    begin
        case keccak_mode_out is
            -- ExpandMask, SamplePolyCBD
            when "0001" =>
                if is_dilithium = '1' then
                    sample_s_axis_tuser <= std_logic_vector_for_sec_level(mode(10 downto 9), "101", "110", "101");
                else
                    sample_s_axis_tuser <= std_logic_vector_for_sec_level(mode(10 downto 9), "010", "001", "001");
                end if;

                sample_s_axis_tvalid <= keccak_m_axis_tvalid;
            -- ExpandA, SampleNTT
            when "0010" =>
                sample_s_axis_tuser <= is_dilithium & "00";
                sample_s_axis_tvalid <= keccak_m_axis_tvalid;
            -- SamplePolyCBD (ETA always == 2)
            when "1011" =>
                sample_s_axis_tuser <= "001";
                sample_s_axis_tvalid <= keccak_m_axis_tvalid;
            when others =>
                sample_s_axis_tuser <= "000";
                sample_s_axis_tvalid <= '0';
        end case;
    end process;

    sample_m_axis_tready <= bram0_can_write;

    -- Sample in ball

    sample_in_ball: entity work.sample_in_ball
    port map (
        clk => clk,
        rst => not running,

        mode => mode(10 downto 9),

        data_in => sample_in_ball_data_in,
        data_in_vld => sample_in_ball_data_in_vld,

        m_axis_tdata => sample_in_ball_m_axis_tdata,
        m_axis_tvalid => sample_in_ball_m_axis_tvalid,
        m_axis_tready => sample_in_ball_m_axis_tready
    );

    sample_in_ball_m_axis_tready <= bram0_can_write;

    sample_in_ball_transactions_last <= '1' when sample_in_ball_transactions_count = 7 else '0';

    proc_sample_in_ball: process(clk) is
    begin
        if rising_edge(clk) then
            sample_in_ball_data_in <= keccak_m_axis_tdata(7 + 8 * sample_in_ball_transactions_count downto 8 * sample_in_ball_transactions_count);
            sample_in_ball_data_in_vld <= keccak_m_axis_tvalid when keccak_mode_out = "1000" else '0';

            if (not running or sig_invalid) = '1' then
                sample_in_ball_transactions_count <= 0;
            else
                if keccak_m_axis_tvalid = '1' and keccak_mode_out = "1000" then
                    if sample_in_ball_transactions_last = '1' then
                        sample_in_ball_transactions_count <= 0;
                    else
                        sample_in_ball_transactions_count <= sample_in_ball_transactions_count + 1;
                    end if;
                end if;
            end if;
        end if;
    end process;

    -- Polynomial multiplication

    poly_mul: entity work.poly_mul
    generic map (
        BRAM_DELAY => BRAM_DELAY
    )
    port map (
        clk => clk,
        rst => not running or sig_invalid,

        start => poly_mul_start,
        rdy => poly_mul_rdy,
        vld => poly_mul_vld,

        mode => poly_mul_mode,

        first_iteration => poly_mul_first_iteration,
        last_iteration => poly_mul_last_iteration,

        inplace_coeffs => poly_mul_inplace_coeffs,
        inplace_op => poly_mul_inplace_op,
        inplace_next => poly_mul_inplace_next,

        coeffs_wea => poly_mul_coeffs_wea,

        coeffs_dina => poly_mul_coeffs_dina,
        coeffs_doutb => poly_mul_coeffs_doutb,

        coeffs_addra => poly_mul_coeffs_addra,
        coeffs_addrb => poly_mul_coeffs_addrb
    );

    poly_mul_inplace_coeffs <= coeffs_fifo_dout(95 downto 0);
    poly_mul_inplace_op <= poly_mul_coeffs_fifo_mode_out(1 downto 0) when poly_mul_offset_we /= "11" else "00";

    poly_mul_coeffs_doutb <= bram0_doutb when poly_mul_coeffs_read_bram_mux_shift_reg(0) = '0' else bram1_doutb;

    poly_mul_state_machine: entity work.poly_mul_state_machine
    port map (
        clk => clk,
        rst => not running,

        mode => mode,

        param_k => param_k,
        param_l => param_l,

        poly_mul_start => poly_mul_start,
        poly_mul_rdy => poly_mul_rdy,
        poly_mul_vld => poly_mul_vld,

        sig_invalid => sig_invalid,

        poly_mul_validity_check_mode => poly_mul_validity_check_mode,

        poly_mul_mode => poly_mul_mode,
        poly_mul_coeffs_fifo_mode_in => poly_mul_coeffs_fifo_mode_in,
        poly_mul_coeffs_fifo_mode_out => poly_mul_coeffs_fifo_mode_out,

        poly_mul_bram_mux => poly_mul_bram_mux,
        poly_mul_first_bram_only => poly_mul_first_bram_only,
        poly_mul_repeat_read => poly_mul_repeat_read,

        poly_mul_offset_we => poly_mul_offset_we,
        poly_mul_addra_offset0 => poly_mul_addra_offset0,
        poly_mul_addra_offset1 => poly_mul_addra_offset1,
        poly_mul_addrb_offset0 => poly_mul_addrb_offset0,
        poly_mul_addrb_offset1 => poly_mul_addrb_offset1,

        poly_mul_running => poly_mul_running,
        poly_mul_half => poly_mul_half,
        poly_mul_half_finished => poly_mul_half_finished,
        poly_mul_finished => poly_mul_finished
    );

    poly_mul_coeffs_addra_last <= (and poly_mul_coeffs_addra(5 downto 0)) when is_dilithium = '1' else (and poly_mul_coeffs_addra(4 downto 0));
    poly_mul_coeffs_addra_mux <= poly_mul_coeffs_addra(6) when is_dilithium = '1' else poly_mul_coeffs_addra(5);
    poly_mul_coeffs_addrb_mux <= poly_mul_coeffs_addrb(6) when is_dilithium = '1' else poly_mul_coeffs_addrb(5);

    -- choose, which BRAM is used for reading
    -- for first iteration of NTT, we read from `bram0`, for remaining from `bram1`
    -- during multiplication (a * b) we switch between `bram0` (a) and `bram1` (b)
    -- when computing NTT of challenge during dilithium sign and verify, it will be stored back to `bram0`, so we use only it
    poly_mul_read_bram_mux <= poly_mul_bram_mux_reg when (poly_mul_first_iteration or poly_mul_coeffs_addrb_mux or poly_mul_first_bram_only) = '1' else '1';

    proc_poly_mul: process(clk) is
    begin
        if rising_edge(clk) then
            if poly_mul_start = '1' then
                poly_mul_bram_mux_reg <= poly_mul_bram_mux;
            end if;

            poly_mul_coeffs_read_bram_mux_shift_reg <= poly_mul_read_bram_mux & poly_mul_coeffs_read_bram_mux_shift_reg(poly_mul_coeffs_read_bram_mux_shift_reg'left downto 1);

            if running = '0' then
                poly_mul_start <= '0';
            else
                -- during kem_dec when message is decrypted we need to wait until it is stored
                if (mode(5) and poly_mul_half and not bram1_stored_dec_m) = '0' then
                    -- make sure `poly_mul_start` is valid only one cycle
                    -- we start computation when we have valid data in bram0 or if we compute on bram1 data
                    poly_mul_start <= not poly_mul_start and ((or bram0_polys_vld) or poly_mul_bram_mux) and poly_mul_rdy and (not (and poly_mul_mode));
                end if;
            end if;
        end if;
    end process;

    -- Coefficients memories

    -- this is used as temporary memory, it stores polynomials from decoding and sampling
    -- it is then used by `poly_mul` either for NTT or multiplication
    -- for NTT it will only read coefficients during first iteration as it will store the NTT results in `bram1`
    -- this way there can be decoded/sampled new polynomials while the computation is happening
    bram0: entity work.bram
    generic map (
        DATA_WIDTH => 96,
        DATA_DEPTH => 512,
        OUT_DELAY => BRAM_DELAY
    )
    port map (
        clk => clk,

        wea => bram0_wea,
        reb => bram0_reb,

        dina => bram0_dina,
        doutb => bram0_doutb,

        addra => bram0_addra,
        addrb => bram0_addrb
    );

    bram0_wea <= ((compress_m_axis_tvalid and compress_mode_decompress) or sample_m_axis_tvalid or sample_in_ball_m_axis_tvalid or (poly_mul_first_bram_only and poly_mul_coeffs_wea)) and bram0_can_write and not bram1_take_bram0;
    bram0_reb <= (bram1_reading_vld or (not poly_mul_read_bram_mux));

    bram0_dina <= compress_m_axis_tdata when (compress_m_axis_tvalid and compress_mode_decompress) = '1' else
        sample_m_axis_tdata when sample_m_axis_tvalid = '1' else
        sample_in_ball_m_axis_tdata when sample_in_ball_m_axis_tvalid = '1' else
        poly_mul_coeffs_dina;

    bram0_addra <= bram0_addra_reg(8 downto 6) & poly_mul_coeffs_addra(5 downto 0) when (poly_mul_first_bram_only and poly_mul_coeffs_wea) = '1' else bram0_addra_reg;
    bram0_addrb <= bram0_addrb_offset(3 downto 1) & (bram0_addrb_offset(0) xor (is_dilithium and bram1_addrb(5))) & bram1_addrb(4 downto 0) when bram1_reading_vld = '1' and (bram1_mode = "0000" or bram1_mode = "1010" or bram1_mode = "1011" or bram1_mode = "1100") else
        bram0_addrb_offset(3 downto 1) & (bram0_addrb_offset(0) xor (is_dilithium and poly_mul_coeffs_addrb(5))) & poly_mul_coeffs_addrb(4 downto 0);

    proc_bram0_can_write: process(all) is
        variable can_write: std_logic;
    begin
        can_write := '0';
        for i in 0 to 7 loop
            can_write := can_write or not bram0_polys_vld(2 * i) or (not bram0_polys_vld(2 * i + 1) and not is_dilithium);
        end loop;

        bram0_can_write <= can_write when mode(6) = '0' or sample_m_axis_tuser(1 downto 0) = "00" else can_write and not (sample_m_axis_tvalid and poly_mul_running);
    end process;

    bram0_addra_reg_last <= (and bram0_addra_reg(5 downto 0)) when is_dilithium = '1' else (and bram0_addra_reg(4 downto 0));
    bram0_addrb_last <= (and bram0_addrb(5 downto 0)) when is_dilithium = '1' else (and bram0_addrb(4 downto 0));

    proc_bram0: process(clk) is
    begin
        if rising_edge(clk) then
            if (not running or sig_invalid) = '1' then
                bram0_addra_reg <= (others => '0');
                bram0_polys_vld <= (others => '0');

                bram0_addrb_offset <= (others => '0');
            else
                if bram0_wea = '1' then
                    if (poly_mul_first_bram_only and poly_mul_coeffs_wea) = '1' then
                        -- indicate valid polynomial if we write last coefficients
                        bram0_polys_vld(to_integer(unsigned(bram0_addra_reg(8 downto 6) & (not is_dilithium and bram0_addra_reg(5))))) <= poly_mul_coeffs_addra_last and poly_mul_last_iteration;
                    else
                        -- indicate valid polynomial if we write last coefficients
                        bram0_polys_vld(to_integer(unsigned(bram0_addra_reg(8 downto 6) & (not is_dilithium and bram0_addra_reg(5))))) <= bram0_addra_reg_last;

                        bram0_addra_reg <= std_logic_vector(unsigned(bram0_addra_reg) + 1);
                    end if;
                end if;

                -- `bram0` is read mostly from `poly_mul`, only during dilithium key_gen it reads at the same time as `bram1`
                if ((bram1_reading_vld or (not poly_mul_read_bram_mux and not poly_mul_repeat_read)) and bram0_addrb_last) = '1' then
                    -- indicate read polynomial
                    bram0_polys_vld(to_integer(unsigned(bram0_addrb_offset))) <= '0';

                    -- when NTT is stored back in `bram0` we increase only offset during first iteration
                    if (not poly_mul_first_bram_only or poly_mul_first_iteration) = '1' then
                        -- offset represents 32 memory locations, for dilithium's polynomial we need 64, for kyber's 32
                        if is_dilithium = '1' then
                            bram0_addrb_offset <= std_logic_vector(unsigned(bram0_addrb_offset) + 2);
                        else
                            bram0_addrb_offset <= std_logic_vector(unsigned(bram0_addrb_offset) + 1);
                        end if;
                    end if;
                end if;
            end if;
        end if;
    end process;

    -- main memory, storing polynomials that are needed for computations
    -- memory offsets:
    -- dilithium - key_gen
    -- 0 -> s1
    -- L -> s2
    -- K + L -> NTT(s1) -> t0
    -- 2 * (K + L) -> t
    -- dilithium - sign:
    -- 0 -> s1
    -- L -> s2
    -- K + L -> t0
    -- 2 * K + L -> y -> y + cs1
    -- 2 * (K + L) -> NTT(w) -> w - cs2
    -- 3 * K + 2 * L -> w -> ct0
    -- dilithium - verify:
    -- 0 -> t1
    -- K -> z
    -- 2 * (K + L) -> w
    -- kyber - pke_key_gen, kem_key_gen:
    -- 0 -> s
    -- K -> e -> A * s + e
    -- 2 * K -> A * s - first part mul (c)
    -- 3 * K -> A * s - first part mul (d)
    -- kyber - pke_dec, kem_dec:
    -- 0 -> s
    -- 2 * K -> u -> s * u - first part mul (c) -> w
    -- 5 * K -> s * u - first part mul (d)
    -- kyber - pke_enc, kem_enc, kem_dec:
    -- K -> t
    -- 2 * K -> m
    -- 2 * K + 1 -> r -> v
    -- 3 * K + 1 -> u
    -- 4 * K + 1 -> A * t - first part mul (c)
    -- 5 * K + 1 -> A * t - first part mul (d)
    -- -----------------
    bram1: entity work.bram
    generic map (
        DATA_WIDTH => 96,
        DATA_DEPTH => 4096,
        OUT_DELAY => BRAM_DELAY
    )
    port map (
        clk => clk,

        wea => bram1_wea,
        reb => bram1_reb,

        dina => bram1_dina,
        doutb => bram1_doutb,

        addra => bram1_addra,
        addrb => bram1_addrb
    );

    bram1_wea <= sample_m_axis_tvalid when bram1_copy_bram0 = '1' else
        compress_m_axis_tvalid when (bram1_take_bram0 or bram1_store_dec_m) = '1' else
        compress_m_axis_tvalid and encode_s_axis_tready when (compress_mode_high_bits and mode(6)) = '1' else
        poly_mul_coeffs_wea and ((poly_mul_offset_we(0) and not poly_mul_coeffs_addra_mux) or (poly_mul_offset_we(1) and poly_mul_coeffs_addra_mux));

    bram1_reb <= bram1_reading_vld or not poly_mul_rdy;

    bram1_dina <= sample_m_axis_tdata when bram1_copy_bram0 = '1' else
        poly_mul_coeffs_dina when poly_mul_running = '1' else
        compress_m_axis_low_bits_tdata when mode(6) = '1' else
        compress_m_axis_tdata;

    bram1_addra <= bram1_addra_reg when (bram1_copy_bram0 or (compress_mode_high_bits and mode(6)) or bram1_store_dec_m) = '1' else
        bram1_addra_reg(11 downto 6) & bram1_addra_reg(5 downto 0) when bram1_take_bram0 = '1' else
        poly_mul_addra_offset1 & (is_dilithium and poly_mul_coeffs_addra(5)) & poly_mul_coeffs_addra(4 downto 0) when poly_mul_coeffs_addra_mux = '1' else
        poly_mul_addra_offset0 & (is_dilithium and poly_mul_coeffs_addra(5)) & poly_mul_coeffs_addra(4 downto 0);

    bram1_addrb <=
        bram1_addrb_offset & bram1_addrb_reg when bram1_reading_vld = '1' else
        poly_mul_addrb_offset1 & (is_dilithium and poly_mul_coeffs_addrb(5)) & poly_mul_coeffs_addrb(4 downto 0) when (poly_mul_coeffs_addrb_mux or poly_mul_first_iteration) = '1' else
        poly_mul_addrb_offset0 & (is_dilithium and poly_mul_coeffs_addrb(5)) & poly_mul_coeffs_addrb(4 downto 0);

    bram1_state_machine: entity work.bram1_state_machine
    port map (
        clk => clk,
        rst => not running or sig_invalid,

        mode => mode,

        param_k => param_k,
        param_l => param_l,

        next_mode => bram1_reading_vld and bram1_addrb_reg_second_to_last,

        bram1_mode => bram1_mode,
        bram1_addrb_offset => bram1_addrb_offset
    );

    -- copies s1, s2 coefficients during dilithium's key_gen
    bram1_copy_bram0 <= '1' when (mode(6) and sample_m_axis_tvalid and not poly_mul_running) = '1' and sample_s_axis_tuser(1 downto 0) /= "00" else '0';

    bram1_take_bram0 <= '1' when (mode(2) and compress_m_axis_tvalid) = '1' and compress_m_axis_tuser = "010000" else
        '1' when ((mode(1) or mode(4) or mode(5)) and compress_m_axis_tvalid) = '1' and (compress_m_axis_tuser = "010000" or compress_m_axis_tuser = "010101") else
        '0';

    bram1_reading_vld <= '0' when bram1_mode = "0000" and unsigned(bram1_addra_reg(11 downto 6)) < param_k + param_l else
        poly_mul_finished when bram1_mode = "0101" or bram1_mode = "1101" else
        poly_mul_first_bram_only and (not coeffs_fifo_dout_vld or (or bram1_addrb_reg)) when bram1_mode = "0011" else
        poly_mul_half_finished and (not coeffs_fifo_dout_vld or (or bram1_addrb_reg)) and (or bram0_polys_vld) when mode(5) = '1' and bram1_mode = "1010" else
        poly_mul_finished and (not coeffs_fifo_dout_vld or (or bram1_addrb_reg)) and (or bram0_polys_vld) when bram1_mode = "1010" else
        poly_mul_finished and (not coeffs_fifo_dout_vld or (or bram1_addrb_reg));

    bram1_addra_reg_kyber_last <= (and bram1_addra_reg(4 downto 0)) and not is_dilithium;
    bram1_addrb_reg_last <= (and bram1_addrb_reg) when is_dilithium = '1' else (and bram1_addrb_reg(4 downto 0));
    bram1_addrb_reg_second_to_last <= '1' when (not is_dilithium or bram1_addrb_reg(5)) & bram1_addrb_reg(4 downto 0) = "111110" else '0';

    bram1_store_dec_m <= compress_m_axis_tvalid and compress_m_axis_tready when compress_m_axis_tuser = "000101" else '0';

    proc_bram1: process(clk) is
    begin
        if rising_edge(clk) then
            if (not running or sig_invalid) = '1' then
                bram1_mode_shift_reg <= (others => (others => '1'));

                -- for kyber pke_enc and kem_enc coefficients are stored from K offset, it is need because for kem_dec is needed both pke_dec and pke_enc and pke_dec starts at offset 0
                bram1_addra_reg <= std_logic_vector(to_unsigned(param_k, 6)) & (5 downto 0 => '0') when (mode(1) or mode(4)) = '1' else (others => '0');
                bram1_addrb_reg <= (others => '0');

                -- indicate decrypted m was stored in `bram1` during kyber's kem_dec
                bram1_stored_dec_m <= '0';
            else
                bram1_mode_shift_reg <= (bram1_mode or (3 downto 0 => not bram1_reading_vld)) & bram1_mode_shift_reg(bram1_mode_shift_reg'left downto 1);

                if (bram1_store_dec_m and bram1_addra_reg_kyber_last) = '1' then
                    bram1_stored_dec_m <= '1';
                end if;

                if (bram1_wea and (bram1_copy_bram0 or bram1_take_bram0 or (compress_mode_high_bits and mode(6)) or bram1_store_dec_m)) = '1' then
                    if bram1_addra_reg_kyber_last = '1' then
                        bram1_addra_reg <= std_logic_vector(unsigned(bram1_addra_reg) + 33);
                    else
                        bram1_addra_reg <= std_logic_vector(unsigned(bram1_addra_reg) + 1);
                    end if;
                end if;

                if bram1_reading_vld = '1' then
                    if bram1_addrb_reg_last = '1' then
                        bram1_addrb_reg <= (others => '0');
                    else
                        bram1_addrb_reg <= std_logic_vector(unsigned(bram1_addrb_reg) + 1);
                    end if;
                end if;
            end if;
        end if;
    end process;

    -- small fifo for short term coefficients storing
    -- it is used for polynomial addition/subtraction, dumping from memory

    coeffs_fifo: entity work.small_fifo
    generic map (
        DATA_WIDTH => 100,
        DATA_DEPTH => 64
    )
    port map (
        clk => clk,
        rst => not running or sig_invalid,

        din => coeffs_fifo_din,
        din_vld => coeffs_fifo_din_vld,

        dout => coeffs_fifo_dout,
        dout_vld => coeffs_fifo_dout_vld,
        dout_rdy => coeffs_fifo_dout_rdy
    );

    proc_coeffs_fifo_in: process(clk) is
    begin
        if rising_edge(clk) then
            -- store coefficients from bram for inplace addition/subtraction with results of polynomial multiplication
            if poly_mul_coeffs_fifo_mode_in = "001" or poly_mul_coeffs_fifo_mode_in = "010" then
                coeffs_fifo_din_vld <= coeffs_fifo_vld(0);

                if coeffs_fifo_vld(0) = '1' then
                    coeffs_fifo_din <= "1111" & bram1_doutb;
                end if;
            elsif poly_mul_coeffs_fifo_mode_out(2) = '1' then
                coeffs_fifo_din_vld <= bram1_wea;

                if bram1_wea = '1' then
                    coeffs_fifo_din <= "1111" & poly_mul_coeffs_dina;
                end if;
            -- store coefficients from `bram1` before outputing or when they should be added to other coefficients
            elsif bram1_mode_shift_reg(0) /= "1111" and bram1_mode_shift_reg(0) /= "0101" then
                coeffs_fifo_din(99 downto 96) <= bram1_mode_shift_reg(0);
                coeffs_fifo_din_vld <= '1';

                for i in 0 to 3 loop
                    case bram1_mode_shift_reg(0) is
                        when "0000" | "1011" | "1100" => coeffs_fifo_din(23 + 24 * i downto 24 * i) <= add_reduce(bram0_doutb(23 + 24 * i downto 24 * i), bram1_doutb(23 + 24 * i downto 24 * i), is_dilithium);
                        when "1010" => coeffs_fifo_din(23 + 24 * i downto 24 * i) <= kyber_sub_reduce(bram0_doutb(23 + 24 * i downto 12 + 24 * i), bram1_doutb(23 + 24 * i downto 12 + 24 * i)) & kyber_sub_reduce(bram0_doutb(11 + 24 * i downto 24 * i), bram1_doutb(11 + 24 * i downto 24 * i));
                        when "1101" => coeffs_fifo_din(23 + 24 * i downto 24 * i) <= kyber_add_reduce(coeffs_fifo_dout(23 + 24 * i downto 12 + 24 * i), bram1_doutb(23 + 24 * i downto 12 + 24 * i)) & kyber_add_reduce(coeffs_fifo_dout(11 + 24 * i downto 24 * i), bram1_doutb(11 + 24 * i downto 24 * i));
                        when others => coeffs_fifo_din(23 + 24 * i downto 24 * i) <= bram1_doutb(23 + 24 * i downto 24 * i);
                    end case;
                end loop;
            else
                coeffs_fifo_din_vld <= '0';
            end if;

            if sig_invalid = '1' then
                coeffs_fifo_din_vld <= '0';
            end if;
        end if;
    end process;

    proc_coeffs_fifo_out: process(all) is
    begin
        coeffs_fifo_dout_rdy <= '0';

        -- stored coefficients for in-place addition/subtraction during polynomial multiplication
        if (poly_mul_coeffs_fifo_mode_out(1 downto 0) = "01" or poly_mul_coeffs_fifo_mode_out(1 downto 0) = "10" or poly_mul_coeffs_fifo_mode_out(1 downto 0) = "11") and poly_mul_offset_we /= "11" then
            coeffs_fifo_dout_rdy <= poly_mul_inplace_next;
        -- stored ct0, before summed with w - cs2
        elsif coeffs_fifo_dout(99 downto 96) = "0100" then
            coeffs_fifo_dout_rdy <= compress_m_axis_tvalid and compress_mode_low_bits;
        -- stored v + e2 before summing with m
        elsif coeffs_fifo_dout(99 downto 96) = "1100" then
            if bram1_mode_shift_reg(0) = "1101" then
                coeffs_fifo_dout_rdy <= '1';
            end if;
        -- for all other valid modes data are fed to `compress` unit
        elsif coeffs_fifo_dout(99 downto 96) /= "1111" then
            coeffs_fifo_dout_rdy <= compress_s_axis_tready;
        end if;
    end process;

    proc_coeffs_fifo: process(clk) is
    begin
        if rising_edge(clk) then
            if (not running or sig_invalid) = '1' then
                coeffs_fifo_vld <= (others => '0');
            else
                coeffs_fifo_vld <= (poly_mul_coeffs_addrb_mux and (not poly_mul_bram_mux_reg)) & coeffs_fifo_vld(coeffs_fifo_vld'left downto 1);
            end if;
        end if;
    end process;

    -- validity checks for dilithium

    validity_check: entity work.validity_check
    port map (
        clk => clk,
        rst => not running,

        mode => validity_check_mode,

        coeffs => validity_check_coeffs,
        coeffs_vld => validity_check_coeffs_vld,

        valid => validity_check_valid,
        valid_vld => validity_check_valid_vld
    );

    validity_check_mode(3 downto 2) <= mode(10 downto 9);
    validity_check_mode(1 downto 0) <= "11" when poly_mul_validity_check_mode = "11" else '0' & (compress_mode_low_bits and compress_m_axis_tvalid);

    validity_check_coeffs <= compress_m_axis_low_bits_tdata when (compress_mode_low_bits and compress_m_axis_tvalid) = '1' else
        compress_m_axis_tdata when (compress_m_axis_tvalid and mode(8)) = '1' and compress_m_axis_tuser(5 downto 1) = "01100" else
        poly_mul_coeffs_dina;
    validity_check_coeffs_vld <= compress_m_axis_tvalid when (compress_mode_low_bits and compress_m_axis_tvalid) = '1' else
        compress_m_axis_tvalid when (compress_m_axis_tvalid and mode(8)) = '1' and compress_m_axis_tuser(5 downto 1) = "01100" else
        poly_mul_coeffs_wea and poly_mul_last_iteration and poly_mul_validity_check_mode(0);

    proc_sig_invalid: process(clk) is
    begin
        if rising_edge(clk) then
            sig_invalid <= (not validity_check_valid and validity_check_valid_vld) or (make_hint_m_axis_tuser and make_hint_m_axis_tvalid);
        end if;
    end process;

    -- make_hint for dilithium

    make_hint: entity work.make_hint
    port map (
        clk => clk,
        rst => not running or sig_invalid,

        mode => mode(10 downto 9),

        coeffs_high_bits => make_hint_coeffs_high_bits,
        coeffs => make_hint_coeffs,
        coeffs_vld => make_hint_coeffs_vld,

        m_axis_tdata => make_hint_m_axis_tdata,
        m_axis_tuser => make_hint_m_axis_tuser,
        m_axis_tvalid => make_hint_m_axis_tvalid,
        m_axis_tready => make_hint_m_axis_tready
    );

    gen_make_hint_in: for i in 0 to 3 generate
        make_hint_coeffs_high_bits(5 + 6 * i downto 6 * i) <= compress_m_axis_tdata(5 + 6 * i downto 6 * i);

        -- first load w1 and then r0 - ct0
        make_hint_coeffs(23 + 24 * i downto 24 * i) <= dilithium_add_reduce(coeffs_fifo_dout(23 + 24 * i downto 24 * i), '0' & compress_m_axis_low_bits_tdata(22 + 24 * i downto 24 * i));
    end generate;

    make_hint_coeffs_vld <= compress_m_axis_tvalid and compress_m_axis_tready and compress_mode_low_bits and coeffs_fifo_dout_vld and poly_mul_finished and mode(7);

    make_hint_m_axis_tready <= '1' when make_hint_m_axis_tuser = '1' else m_axis_tready when out_mode(2) = '1' else '0';

    use_hint: entity work.use_hint
    port map (
        clk => clk,
        rst => not running,

        mode => mode(10 downto 9),

        s_axis_tdata => use_hint_s_axis_tdata,
        s_axis_tvalid => use_hint_s_axis_tvalid,
        s_axis_tready => use_hint_s_axis_tready,

        m_axis_tdata => use_hint_m_axis_tdata,
        m_axis_tvalid => use_hint_m_axis_tvalid,
        m_axis_tready => use_hint_m_axis_tready,

        hints_invalid => use_hint_hints_invalid
    );

    gen_use_hint_in: for i in 0 to 3 generate
        use_hint_s_axis_tdata(15 + 16 * i downto 16 * i) <= s_axis_tdata(15 + 16 * i downto 16 * i) when in_mode(3) = '1' else
            compress_m_axis_low_bits_tdata(22 + 24 * i) & (14 downto 6 => '0') & compress_m_axis_tdata(5 + 24 * i downto 24 * i);
    end generate;

    use_hint_s_axis_tvalid <= s_axis_tvalid when in_mode(3) = '1' else compress_m_axis_tvalid and compress_mode_high_bits and mode(8);

    use_hint_m_axis_tready <= encode_s_axis_tready;

    -- input logic

    in_state_machine: entity work.in_state_machine
    port map (
        clk => clk,
        rst => not running,

        mode => mode,

        next_mode => in_next_mode,

        in_mode => in_mode,
        in_decode_mode => in_decode_mode,

        in_transaction_offset => in_transaction_offset
    );

    in_next_mode <= s_axis_tvalid and in_rdy and s_axis_tlast when in_mode = "0100" else s_axis_tvalid and in_rdy;

    in_rdy <= '0' when in_mode = "0000" else (not in_mode(1) or decode_s_axis_tready) and (not in_mode(2) or (keccak_s_axis_tready and not keccak_last_absorbing_iteration and keccak_source(1))) and (not in_mode(3) or use_hint_s_axis_tready);

    -- output logic

    out_state_machine: entity work.out_state_machine
    port map (
        clk => clk,
        rst => not running,

        mode => mode,

        next_mode => out_vld and m_axis_tready,

        out_mode => out_mode,

        out_transaction_last => out_transaction_last,

        out_transaction_offset => out_transaction_offset_tmp,
        out_pk => out_pk
    );

    -- for invalid ciphertext read invalid key
    out_transaction_offset <= 16 + out_transaction_offset_tmp when (mode(5) and not cipher_eq) = '1' else out_transaction_offset_tmp;

    with out_mode select out_data <=
        current_data when "001",
        encode_m_axis_tdata when "010",
        make_hint_m_axis_tdata when others;

    out_vld <= outputing when out_mode(0) = '1' else
        encode_m_axis_tvalid and keccak_s_axis_tready and not keccak_last_absorbing_iteration and not keccak_source(0) when out_mode(1) = '1' and (keccak_mode_in = "0011" or keccak_mode_in = "1010") else
        encode_m_axis_tvalid when out_mode(1) = '1' else
        make_hint_m_axis_tvalid;

    proc_out: process(clk) is
    begin
        if rising_edge(clk) then
            if mode(7) = '1' then
                outputing <= not make_hint_m_axis_tuser and make_hint_m_axis_tvalid;
            else
                outputing <= ((rho_prime_vld and out_pk and (not mode(5) or cipher_eq_vld)) or (c_vld and not mode(4) and not mode(5))) and poly_mul_finished;
            end if;
        end if;
    end process;

    -- verify

    proc_verify: process(clk) is
    begin
        if rising_edge(clk) then
            if running = '0' then
                verified <= '1';
                verified_vld <= '0';
            else
                if (not validity_check_valid and validity_check_valid_vld) = '1' then
                    verified <= '0';
                    verified_vld <= '1';
                end if;

                if use_hint_hints_invalid = '1' then
                    verified <= '0';
                    verified_vld <= '1';
                end if;

                if keccak_m_axis_tvalid = '1' and keccak_mode_out = "0111" then
                    if current_data /= keccak_m_axis_tdata then
                        verified <= '0';
                    end if;

                    verified_vld <= keccak_out_transactions_last;
                end if;
            end if;
        end if;
    end process;

    cipher_fifo: entity work.small_fifo
    generic map (
        DATA_WIDTH => 64,
        DATA_DEPTH => 256
    )
    port map (
        clk => clk,
        rst => not running,

        din => cipher_fifo_din,
        din_vld => cipher_fifo_din_vld,

        dout => cipher_fifo_dout,
        dout_vld => cipher_fifo_dout_vld,
        dout_rdy => cipher_fifo_dout_rdy
    );

    cipher_fifo_din <= s_axis_tdata;
    cipher_fifo_din_vld <= s_axis_tvalid and decode_s_axis_tready and keccak_s_axis_tready and not keccak_last_absorbing_iteration and keccak_source(1) when in_decode_mode /= "0000" else '0';

    cipher_fifo_dout_rdy <= (encode_m_axis_tvalid and rho_prime_vld);

    with mode(10 downto 9) select cipher_transactions_count_last <=
        95 when "00",
        135 when "01",
        195 when others;

    cipher_transactions_last <= '1' when cipher_transactions_count = cipher_transactions_count_last else '0';

    proc_cipher: process(clk) is
    begin
        if rising_edge(clk) then
            if running = '0' then
                cipher_eq <= '1';
                cipher_eq_vld <= '0';

                cipher_transactions_count <= 0;
            else
                if (encode_m_axis_tvalid and rho_prime_vld) = '1' then
                    if encode_m_axis_tdata /= cipher_fifo_dout then
                        cipher_eq <= '0';
                    end if;

                    if cipher_transactions_last = '1' then
                        cipher_eq_vld <= '1';

                        cipher_transactions_count <= 0;
                    else
                        cipher_transactions_count <= cipher_transactions_count + 1;
                    end if;
                end if;
            end if;
        end if;
    end process;

    proc_debug: process(all) is
    begin
        if SIMULATION then
            for i in 0 to 31 loop
                DATA_DEBUG(63 + 64 * i downto 64 * i) <= data(i);
            end loop;
        end if;
    end process;
end;
