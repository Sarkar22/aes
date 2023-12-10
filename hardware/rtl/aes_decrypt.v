// Pipelined AES decryption core — direct inverse cipher (FIPS 197 §5.3)
// Latency: Nr+1 clock cycles  Throughput: 1 block/cycle
// KEY_W = 128 → Nr=10  |  192 → Nr=12  |  256 → Nr=14
module aes_decrypt #(
    parameter KEY_W = 128
) (
    input              clk,
    input              rst,
    input              valid_in,
    input  [127:0]     ciphertext,
    input  [KEY_W-1:0] key,
    output reg         valid_out,
    output reg [127:0] plaintext
);

localparam Nr = (KEY_W == 128) ? 10 : (KEY_W == 192) ? 12 : 14;

// Combinational key expansion (same schedule as encryption)
wire [(Nr+1)*128-1:0] round_keys;
aes_keyexp #(.KEY_W(KEY_W)) u_keyexp (.key(key), .round_keys(round_keys));

// Pipeline state registers
reg [127:0] pipe [0:Nr-1];
reg         vpipe [0:Nr-1];

// Stage 0: initial AddRoundKey with rk[Nr] (decryption starts from last round key)
wire [127:0] stage0_out = ciphertext ^ round_keys[Nr*128 +: 128];

always @(posedge clk) begin
    if (rst) begin pipe[0] <= 128'b0; vpipe[0] <= 1'b0; end
    else     begin pipe[0] <= stage0_out; vpipe[0] <= valid_in; end
end

// Stages 1..Nr-1: InvShiftRows + InvSubBytes + AddRoundKey(rk[Nr-r]) + InvMixColumns
// Round key index for stage r is rk[Nr-r]
genvar r;
generate
    for (r = 1; r <= Nr-1; r = r+1) begin : mid_rounds
        wire [127:0] rout;
        aes_inv_round #(.FINAL(0)) u_r (
            .state_in (pipe[r-1]),
            .round_key(round_keys[(Nr-r)*128 +: 128]),
            .state_out(rout)
        );
        always @(posedge clk) begin
            if (rst) begin pipe[r] <= 128'b0; vpipe[r] <= 1'b0; end
            else     begin pipe[r] <= rout;   vpipe[r] <= vpipe[r-1]; end
        end
    end
endgenerate

// Stage Nr: final inverse round with rk[0], no InvMixColumns
wire [127:0] final_out;
aes_inv_round #(.FINAL(1)) u_final (
    .state_in (pipe[Nr-1]),
    .round_key(round_keys[0*128 +: 128]),
    .state_out(final_out)
);

always @(posedge clk) begin
    if (rst) begin plaintext <= 128'b0; valid_out <= 1'b0; end
    else     begin plaintext <= final_out; valid_out <= vpipe[Nr-1]; end
end

endmodule
