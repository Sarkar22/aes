// One AES encryption round: SubBytes + ShiftRows + MixColumns + AddRoundKey
// FINAL=1 skips MixColumns (last round per FIPS 197 §5.1)
// State layout: [127:120]=byte0(row0,col0) ... [7:0]=byte15(row3,col3)
module aes_round #(
    parameter FINAL = 0
) (
    input  [127:0] state_in,
    input  [127:0] round_key,
    output [127:0] state_out
);

// --- SubBytes: 16 S-box instances ---
wire [7:0] sb0,  sb1,  sb2,  sb3,
           sb4,  sb5,  sb6,  sb7,
           sb8,  sb9,  sb10, sb11,
           sb12, sb13, sb14, sb15;

aes_sbox u0  (.in(state_in[127:120]), .out(sb0));
aes_sbox u1  (.in(state_in[119:112]), .out(sb1));
aes_sbox u2  (.in(state_in[111:104]), .out(sb2));
aes_sbox u3  (.in(state_in[103:96]),  .out(sb3));
aes_sbox u4  (.in(state_in[95:88]),   .out(sb4));
aes_sbox u5  (.in(state_in[87:80]),   .out(sb5));
aes_sbox u6  (.in(state_in[79:72]),   .out(sb6));
aes_sbox u7  (.in(state_in[71:64]),   .out(sb7));
aes_sbox u8  (.in(state_in[63:56]),   .out(sb8));
aes_sbox u9  (.in(state_in[55:48]),   .out(sb9));
aes_sbox u10 (.in(state_in[47:40]),   .out(sb10));
aes_sbox u11 (.in(state_in[39:32]),   .out(sb11));
aes_sbox u12 (.in(state_in[31:24]),   .out(sb12));
aes_sbox u13 (.in(state_in[23:16]),   .out(sb13));
aes_sbox u14 (.in(state_in[15:8]),    .out(sb14));
aes_sbox u15 (.in(state_in[7:0]),     .out(sb15));

// --- ShiftRows: wire-only rearrangement (FIPS 197 §5.1.2)
// sr[row][col] = sb[row][(col+row)%4]
// col0: row0=sb0, row1=sb5, row2=sb10, row3=sb15
// col1: row0=sb4, row1=sb9,  row2=sb14, row3=sb3
// col2: row0=sb8, row1=sb13, row2=sb2,  row3=sb7
// col3: row0=sb12,row1=sb1,  row2=sb6,  row3=sb11

// --- MixColumns per column (FIPS 197 §5.1.3)
// xtime(a) = {a[6:0],1'b0} ^ (a[7] ? 8'h1b : 8'h00)
// col_out[0] = x2(a0)^x3(a1)^a2^a3
// col_out[1] = a0^x2(a1)^x3(a2)^a3
// col_out[2] = a0^a1^x2(a2)^x3(a3)
// col_out[3] = x3(a0)^a1^a2^x2(a3)

// Column 0: a0=sb0, a1=sb5, a2=sb10, a3=sb15
wire [7:0] x2_c0a0 = {sb0[6:0],1'b0}  ^ (sb0[7]  ? 8'h1b : 8'h00);
wire [7:0] x2_c0a1 = {sb5[6:0],1'b0}  ^ (sb5[7]  ? 8'h1b : 8'h00);
wire [7:0] x2_c0a2 = {sb10[6:0],1'b0} ^ (sb10[7] ? 8'h1b : 8'h00);
wire [7:0] x2_c0a3 = {sb15[6:0],1'b0} ^ (sb15[7] ? 8'h1b : 8'h00);
wire [7:0] mc_c0_0 = x2_c0a0 ^ (x2_c0a1^sb5)  ^ sb10 ^ sb15;
wire [7:0] mc_c0_1 = sb0 ^ x2_c0a1 ^ (x2_c0a2^sb10) ^ sb15;
wire [7:0] mc_c0_2 = sb0 ^ sb5 ^ x2_c0a2 ^ (x2_c0a3^sb15);
wire [7:0] mc_c0_3 = (x2_c0a0^sb0) ^ sb5 ^ sb10 ^ x2_c0a3;

// Column 1: a0=sb4, a1=sb9, a2=sb14, a3=sb3
wire [7:0] x2_c1a0 = {sb4[6:0],1'b0}  ^ (sb4[7]  ? 8'h1b : 8'h00);
wire [7:0] x2_c1a1 = {sb9[6:0],1'b0}  ^ (sb9[7]  ? 8'h1b : 8'h00);
wire [7:0] x2_c1a2 = {sb14[6:0],1'b0} ^ (sb14[7] ? 8'h1b : 8'h00);
wire [7:0] x2_c1a3 = {sb3[6:0],1'b0}  ^ (sb3[7]  ? 8'h1b : 8'h00);
wire [7:0] mc_c1_0 = x2_c1a0 ^ (x2_c1a1^sb9)  ^ sb14 ^ sb3;
wire [7:0] mc_c1_1 = sb4 ^ x2_c1a1 ^ (x2_c1a2^sb14) ^ sb3;
wire [7:0] mc_c1_2 = sb4 ^ sb9 ^ x2_c1a2 ^ (x2_c1a3^sb3);
wire [7:0] mc_c1_3 = (x2_c1a0^sb4) ^ sb9 ^ sb14 ^ x2_c1a3;

// Column 2: a0=sb8, a1=sb13, a2=sb2, a3=sb7
wire [7:0] x2_c2a0 = {sb8[6:0],1'b0}  ^ (sb8[7]  ? 8'h1b : 8'h00);
wire [7:0] x2_c2a1 = {sb13[6:0],1'b0} ^ (sb13[7] ? 8'h1b : 8'h00);
wire [7:0] x2_c2a2 = {sb2[6:0],1'b0}  ^ (sb2[7]  ? 8'h1b : 8'h00);
wire [7:0] x2_c2a3 = {sb7[6:0],1'b0}  ^ (sb7[7]  ? 8'h1b : 8'h00);
wire [7:0] mc_c2_0 = x2_c2a0 ^ (x2_c2a1^sb13) ^ sb2 ^ sb7;
wire [7:0] mc_c2_1 = sb8 ^ x2_c2a1 ^ (x2_c2a2^sb2)  ^ sb7;
wire [7:0] mc_c2_2 = sb8 ^ sb13 ^ x2_c2a2 ^ (x2_c2a3^sb7);
wire [7:0] mc_c2_3 = (x2_c2a0^sb8) ^ sb13 ^ sb2 ^ x2_c2a3;

// Column 3: a0=sb12, a1=sb1, a2=sb6, a3=sb11
wire [7:0] x2_c3a0 = {sb12[6:0],1'b0} ^ (sb12[7] ? 8'h1b : 8'h00);
wire [7:0] x2_c3a1 = {sb1[6:0],1'b0}  ^ (sb1[7]  ? 8'h1b : 8'h00);
wire [7:0] x2_c3a2 = {sb6[6:0],1'b0}  ^ (sb6[7]  ? 8'h1b : 8'h00);
wire [7:0] x2_c3a3 = {sb11[6:0],1'b0} ^ (sb11[7] ? 8'h1b : 8'h00);
wire [7:0] mc_c3_0 = x2_c3a0 ^ (x2_c3a1^sb1)  ^ sb6 ^ sb11;
wire [7:0] mc_c3_1 = sb12 ^ x2_c3a1 ^ (x2_c3a2^sb6)  ^ sb11;
wire [7:0] mc_c3_2 = sb12 ^ sb1 ^ x2_c3a2 ^ (x2_c3a3^sb11);
wire [7:0] mc_c3_3 = (x2_c3a0^sb12) ^ sb1 ^ sb6 ^ x2_c3a3;

// --- AddRoundKey: select MixColumns output or ShiftRows output for FINAL ---
// Non-final: use MixColumns output; Final: use ShiftRows output directly
wire [127:0] pre_ark;
generate
    if (FINAL == 0) begin : mix
        assign pre_ark = {mc_c0_0, mc_c0_1, mc_c0_2, mc_c0_3,
                          mc_c1_0, mc_c1_1, mc_c1_2, mc_c1_3,
                          mc_c2_0, mc_c2_1, mc_c2_2, mc_c2_3,
                          mc_c3_0, mc_c3_1, mc_c3_2, mc_c3_3};
    end else begin : nomix
        assign pre_ark = {sb0,  sb5,  sb10, sb15,
                          sb4,  sb9,  sb14, sb3,
                          sb8,  sb13, sb2,  sb7,
                          sb12, sb1,  sb6,  sb11};
    end
endgenerate

assign state_out = pre_ark ^ round_key;

endmodule
