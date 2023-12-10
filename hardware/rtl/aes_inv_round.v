// One AES decryption round (direct inverse cipher, FIPS 197 §5.3):
// InvShiftRows + InvSubBytes + AddRoundKey + InvMixColumns
// FINAL=1 skips InvMixColumns (first round of decryption pipeline)
module aes_inv_round #(
    parameter FINAL = 0
) (
    input  [127:0] state_in,
    input  [127:0] round_key,
    output [127:0] state_out
);

// --- InvShiftRows: wire-only rearrangement (FIPS 197 §5.3.1)
// isr[row][col] = s[row][(col+4-row)%4]
// col0: row0=s[0], row1=s[13], row2=s[10], row3=s[7]
// col1: row0=s[4], row1=s[1],  row2=s[14], row3=s[11]
// col2: row0=s[8], row1=s[5],  row2=s[2],  row3=s[15]
// col3: row0=s[12],row1=s[9],  row2=s[6],  row3=s[3]
wire [7:0] s0  = state_in[127:120]; wire [7:0] s1  = state_in[119:112];
wire [7:0] s2  = state_in[111:104]; wire [7:0] s3  = state_in[103:96];
wire [7:0] s4  = state_in[95:88];   wire [7:0] s5  = state_in[87:80];
wire [7:0] s6  = state_in[79:72];   wire [7:0] s7  = state_in[71:64];
wire [7:0] s8  = state_in[63:56];   wire [7:0] s9  = state_in[55:48];
wire [7:0] s10 = state_in[47:40];   wire [7:0] s11 = state_in[39:32];
wire [7:0] s12 = state_in[31:24];   wire [7:0] s13 = state_in[23:16];
wire [7:0] s14 = state_in[15:8];    wire [7:0] s15 = state_in[7:0];

// --- InvSubBytes: 16 inverse S-box instances ---
wire [7:0] isb0,  isb1,  isb2,  isb3,
           isb4,  isb5,  isb6,  isb7,
           isb8,  isb9,  isb10, isb11,
           isb12, isb13, isb14, isb15;

// Apply InvSubBytes after InvShiftRows reordering
aes_inv_sbox u0  (.in(s0),  .out(isb0));
aes_inv_sbox u1  (.in(s13), .out(isb1));
aes_inv_sbox u2  (.in(s10), .out(isb2));
aes_inv_sbox u3  (.in(s7),  .out(isb3));
aes_inv_sbox u4  (.in(s4),  .out(isb4));
aes_inv_sbox u5  (.in(s1),  .out(isb5));
aes_inv_sbox u6  (.in(s14), .out(isb6));
aes_inv_sbox u7  (.in(s11), .out(isb7));
aes_inv_sbox u8  (.in(s8),  .out(isb8));
aes_inv_sbox u9  (.in(s5),  .out(isb9));
aes_inv_sbox u10 (.in(s2),  .out(isb10));
aes_inv_sbox u11 (.in(s15), .out(isb11));
aes_inv_sbox u12 (.in(s12), .out(isb12));
aes_inv_sbox u13 (.in(s9),  .out(isb13));
aes_inv_sbox u14 (.in(s6),  .out(isb14));
aes_inv_sbox u15 (.in(s3),  .out(isb15));

// --- AddRoundKey ---
wire [127:0] ark_out;
assign ark_out = {isb0,  isb1,  isb2,  isb3,
                  isb4,  isb5,  isb6,  isb7,
                  isb8,  isb9,  isb10, isb11,
                  isb12, isb13, isb14, isb15} ^ round_key;

// --- InvMixColumns (FIPS 197 §5.3.3), GF(2^8) mults by 9,11,13,14 ---
// x2(a) = {a[6:0],1'b0} ^ (a[7] ? 8'h1b : 8'h00)
// x4(a) = x2(x2(a)), x8(a) = x2(x4(a))
// x9=x8^x1, xb=x8^x2^x1, xd=x8^x4^x1, xe=x8^x4^x2
// col_out[0] = xe*a0 ^ xb*a1 ^ xd*a2 ^ x9*a3
// col_out[1] = x9*a0 ^ xe*a1 ^ xb*a2 ^ xd*a3
// col_out[2] = xd*a0 ^ x9*a1 ^ xe*a2 ^ xb*a3
// col_out[3] = xb*a0 ^ xd*a1 ^ x9*a2 ^ xe*a3

// Column 0
wire [7:0] a0_c0=ark_out[127:120], a1_c0=ark_out[119:112],
           a2_c0=ark_out[111:104], a3_c0=ark_out[103:96];
wire [7:0] x2_c0_0={a0_c0[6:0],1'b0}^(a0_c0[7]?8'h1b:8'h00);
wire [7:0] x4_c0_0={x2_c0_0[6:0],1'b0}^(x2_c0_0[7]?8'h1b:8'h00);
wire [7:0] x8_c0_0={x4_c0_0[6:0],1'b0}^(x4_c0_0[7]?8'h1b:8'h00);
wire [7:0] x2_c0_1={a1_c0[6:0],1'b0}^(a1_c0[7]?8'h1b:8'h00);
wire [7:0] x4_c0_1={x2_c0_1[6:0],1'b0}^(x2_c0_1[7]?8'h1b:8'h00);
wire [7:0] x8_c0_1={x4_c0_1[6:0],1'b0}^(x4_c0_1[7]?8'h1b:8'h00);
wire [7:0] x2_c0_2={a2_c0[6:0],1'b0}^(a2_c0[7]?8'h1b:8'h00);
wire [7:0] x4_c0_2={x2_c0_2[6:0],1'b0}^(x2_c0_2[7]?8'h1b:8'h00);
wire [7:0] x8_c0_2={x4_c0_2[6:0],1'b0}^(x4_c0_2[7]?8'h1b:8'h00);
wire [7:0] x2_c0_3={a3_c0[6:0],1'b0}^(a3_c0[7]?8'h1b:8'h00);
wire [7:0] x4_c0_3={x2_c0_3[6:0],1'b0}^(x2_c0_3[7]?8'h1b:8'h00);
wire [7:0] x8_c0_3={x4_c0_3[6:0],1'b0}^(x4_c0_3[7]?8'h1b:8'h00);
wire [7:0] imc_c0_0=(x8_c0_0^x4_c0_0^x2_c0_0)^(x8_c0_1^x2_c0_1^a1_c0)^(x8_c0_2^x4_c0_2^a2_c0)^(x8_c0_3^a3_c0);
wire [7:0] imc_c0_1=(x8_c0_0^a0_c0)^(x8_c0_1^x4_c0_1^x2_c0_1)^(x8_c0_2^x2_c0_2^a2_c0)^(x8_c0_3^x4_c0_3^a3_c0);
wire [7:0] imc_c0_2=(x8_c0_0^x4_c0_0^a0_c0)^(x8_c0_1^a1_c0)^(x8_c0_2^x4_c0_2^x2_c0_2)^(x8_c0_3^x2_c0_3^a3_c0);
wire [7:0] imc_c0_3=(x8_c0_0^x2_c0_0^a0_c0)^(x8_c0_1^x4_c0_1^a1_c0)^(x8_c0_2^a2_c0)^(x8_c0_3^x4_c0_3^x2_c0_3);

// Column 1
wire [7:0] a0_c1=ark_out[95:88],  a1_c1=ark_out[87:80],
           a2_c1=ark_out[79:72],  a3_c1=ark_out[71:64];
wire [7:0] x2_c1_0={a0_c1[6:0],1'b0}^(a0_c1[7]?8'h1b:8'h00);
wire [7:0] x4_c1_0={x2_c1_0[6:0],1'b0}^(x2_c1_0[7]?8'h1b:8'h00);
wire [7:0] x8_c1_0={x4_c1_0[6:0],1'b0}^(x4_c1_0[7]?8'h1b:8'h00);
wire [7:0] x2_c1_1={a1_c1[6:0],1'b0}^(a1_c1[7]?8'h1b:8'h00);
wire [7:0] x4_c1_1={x2_c1_1[6:0],1'b0}^(x2_c1_1[7]?8'h1b:8'h00);
wire [7:0] x8_c1_1={x4_c1_1[6:0],1'b0}^(x4_c1_1[7]?8'h1b:8'h00);
wire [7:0] x2_c1_2={a2_c1[6:0],1'b0}^(a2_c1[7]?8'h1b:8'h00);
wire [7:0] x4_c1_2={x2_c1_2[6:0],1'b0}^(x2_c1_2[7]?8'h1b:8'h00);
wire [7:0] x8_c1_2={x4_c1_2[6:0],1'b0}^(x4_c1_2[7]?8'h1b:8'h00);
wire [7:0] x2_c1_3={a3_c1[6:0],1'b0}^(a3_c1[7]?8'h1b:8'h00);
wire [7:0] x4_c1_3={x2_c1_3[6:0],1'b0}^(x2_c1_3[7]?8'h1b:8'h00);
wire [7:0] x8_c1_3={x4_c1_3[6:0],1'b0}^(x4_c1_3[7]?8'h1b:8'h00);
wire [7:0] imc_c1_0=(x8_c1_0^x4_c1_0^x2_c1_0)^(x8_c1_1^x2_c1_1^a1_c1)^(x8_c1_2^x4_c1_2^a2_c1)^(x8_c1_3^a3_c1);
wire [7:0] imc_c1_1=(x8_c1_0^a0_c1)^(x8_c1_1^x4_c1_1^x2_c1_1)^(x8_c1_2^x2_c1_2^a2_c1)^(x8_c1_3^x4_c1_3^a3_c1);
wire [7:0] imc_c1_2=(x8_c1_0^x4_c1_0^a0_c1)^(x8_c1_1^a1_c1)^(x8_c1_2^x4_c1_2^x2_c1_2)^(x8_c1_3^x2_c1_3^a3_c1);
wire [7:0] imc_c1_3=(x8_c1_0^x2_c1_0^a0_c1)^(x8_c1_1^x4_c1_1^a1_c1)^(x8_c1_2^a2_c1)^(x8_c1_3^x4_c1_3^x2_c1_3);

// Column 2
wire [7:0] a0_c2=ark_out[63:56],  a1_c2=ark_out[55:48],
           a2_c2=ark_out[47:40],  a3_c2=ark_out[39:32];
wire [7:0] x2_c2_0={a0_c2[6:0],1'b0}^(a0_c2[7]?8'h1b:8'h00);
wire [7:0] x4_c2_0={x2_c2_0[6:0],1'b0}^(x2_c2_0[7]?8'h1b:8'h00);
wire [7:0] x8_c2_0={x4_c2_0[6:0],1'b0}^(x4_c2_0[7]?8'h1b:8'h00);
wire [7:0] x2_c2_1={a1_c2[6:0],1'b0}^(a1_c2[7]?8'h1b:8'h00);
wire [7:0] x4_c2_1={x2_c2_1[6:0],1'b0}^(x2_c2_1[7]?8'h1b:8'h00);
wire [7:0] x8_c2_1={x4_c2_1[6:0],1'b0}^(x4_c2_1[7]?8'h1b:8'h00);
wire [7:0] x2_c2_2={a2_c2[6:0],1'b0}^(a2_c2[7]?8'h1b:8'h00);
wire [7:0] x4_c2_2={x2_c2_2[6:0],1'b0}^(x2_c2_2[7]?8'h1b:8'h00);
wire [7:0] x8_c2_2={x4_c2_2[6:0],1'b0}^(x4_c2_2[7]?8'h1b:8'h00);
wire [7:0] x2_c2_3={a3_c2[6:0],1'b0}^(a3_c2[7]?8'h1b:8'h00);
wire [7:0] x4_c2_3={x2_c2_3[6:0],1'b0}^(x2_c2_3[7]?8'h1b:8'h00);
wire [7:0] x8_c2_3={x4_c2_3[6:0],1'b0}^(x4_c2_3[7]?8'h1b:8'h00);
wire [7:0] imc_c2_0=(x8_c2_0^x4_c2_0^x2_c2_0)^(x8_c2_1^x2_c2_1^a1_c2)^(x8_c2_2^x4_c2_2^a2_c2)^(x8_c2_3^a3_c2);
wire [7:0] imc_c2_1=(x8_c2_0^a0_c2)^(x8_c2_1^x4_c2_1^x2_c2_1)^(x8_c2_2^x2_c2_2^a2_c2)^(x8_c2_3^x4_c2_3^a3_c2);
wire [7:0] imc_c2_2=(x8_c2_0^x4_c2_0^a0_c2)^(x8_c2_1^a1_c2)^(x8_c2_2^x4_c2_2^x2_c2_2)^(x8_c2_3^x2_c2_3^a3_c2);
wire [7:0] imc_c2_3=(x8_c2_0^x2_c2_0^a0_c2)^(x8_c2_1^x4_c2_1^a1_c2)^(x8_c2_2^a2_c2)^(x8_c2_3^x4_c2_3^x2_c2_3);

// Column 3
wire [7:0] a0_c3=ark_out[31:24],  a1_c3=ark_out[23:16],
           a2_c3=ark_out[15:8],   a3_c3=ark_out[7:0];
wire [7:0] x2_c3_0={a0_c3[6:0],1'b0}^(a0_c3[7]?8'h1b:8'h00);
wire [7:0] x4_c3_0={x2_c3_0[6:0],1'b0}^(x2_c3_0[7]?8'h1b:8'h00);
wire [7:0] x8_c3_0={x4_c3_0[6:0],1'b0}^(x4_c3_0[7]?8'h1b:8'h00);
wire [7:0] x2_c3_1={a1_c3[6:0],1'b0}^(a1_c3[7]?8'h1b:8'h00);
wire [7:0] x4_c3_1={x2_c3_1[6:0],1'b0}^(x2_c3_1[7]?8'h1b:8'h00);
wire [7:0] x8_c3_1={x4_c3_1[6:0],1'b0}^(x4_c3_1[7]?8'h1b:8'h00);
wire [7:0] x2_c3_2={a2_c3[6:0],1'b0}^(a2_c3[7]?8'h1b:8'h00);
wire [7:0] x4_c3_2={x2_c3_2[6:0],1'b0}^(x2_c3_2[7]?8'h1b:8'h00);
wire [7:0] x8_c3_2={x4_c3_2[6:0],1'b0}^(x4_c3_2[7]?8'h1b:8'h00);
wire [7:0] x2_c3_3={a3_c3[6:0],1'b0}^(a3_c3[7]?8'h1b:8'h00);
wire [7:0] x4_c3_3={x2_c3_3[6:0],1'b0}^(x2_c3_3[7]?8'h1b:8'h00);
wire [7:0] x8_c3_3={x4_c3_3[6:0],1'b0}^(x4_c3_3[7]?8'h1b:8'h00);
wire [7:0] imc_c3_0=(x8_c3_0^x4_c3_0^x2_c3_0)^(x8_c3_1^x2_c3_1^a1_c3)^(x8_c3_2^x4_c3_2^a2_c3)^(x8_c3_3^a3_c3);
wire [7:0] imc_c3_1=(x8_c3_0^a0_c3)^(x8_c3_1^x4_c3_1^x2_c3_1)^(x8_c3_2^x2_c3_2^a2_c3)^(x8_c3_3^x4_c3_3^a3_c3);
wire [7:0] imc_c3_2=(x8_c3_0^x4_c3_0^a0_c3)^(x8_c3_1^a1_c3)^(x8_c3_2^x4_c3_2^x2_c3_2)^(x8_c3_3^x2_c3_3^a3_c3);
wire [7:0] imc_c3_3=(x8_c3_0^x2_c3_0^a0_c3)^(x8_c3_1^x4_c3_1^a1_c3)^(x8_c3_2^a2_c3)^(x8_c3_3^x4_c3_3^x2_c3_3);

generate
    if (FINAL == 0) begin : invmix
        assign state_out = {imc_c0_0, imc_c0_1, imc_c0_2, imc_c0_3,
                            imc_c1_0, imc_c1_1, imc_c1_2, imc_c1_3,
                            imc_c2_0, imc_c2_1, imc_c2_2, imc_c2_3,
                            imc_c3_0, imc_c3_1, imc_c3_2, imc_c3_3};
    end else begin : noinvmix
        assign state_out = ark_out;
    end
endgenerate

endmodule
