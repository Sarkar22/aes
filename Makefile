RTL_DIR  = hardware/rtl
SIM_DIR  = hardware/sim

RTL_SRC  = $(RTL_DIR)/aes_encrypt.v   \
           $(RTL_DIR)/aes_decrypt.v   \
           $(RTL_DIR)/aes_round.v     \
           $(RTL_DIR)/aes_inv_round.v \
           $(RTL_DIR)/aes_keyexp.v    \
           $(RTL_DIR)/aes_sbox.v      \
           $(RTL_DIR)/aes_inv_sbox.v

SIM_TB   = $(SIM_DIR)/aes_tb.v
SIM_VVP  = $(SIM_DIR)/aes_tb.vvp

.PHONY: sim sw clean

sim: $(SIM_VVP)
	vvp $(SIM_VVP)

$(SIM_VVP): $(SIM_TB) $(RTL_SRC)
	iverilog -g2001 -o $@ $(SIM_TB) $(RTL_SRC)

sw:
	python3 software/aes.py

clean:
	rm -f $(SIM_DIR)/*.vvp $(SIM_DIR)/*.vcd
