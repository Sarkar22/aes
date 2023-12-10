// AES combinational key expansion (FIPS 197 §5.2)
// KEY_W = 128 → Nr=10, 11 round keys; 192 → Nr=12, 13 rks; 256 → Nr=14, 15 rks
// round_keys[i*128 +: 128] = rk[i]
module aes_keyexp #(
    parameter KEY_W = 128
) (
    input  [KEY_W-1:0]      key,
    output [(Nr+1)*128-1:0] round_keys
);

localparam Nr = (KEY_W == 128) ? 10 : (KEY_W == 192) ? 12 : 14;

generate

// =========================================================================
if (KEY_W == 128) begin : g128
// =========================================================================
    wire [31:0] w0=key[127:96], w1=key[95:64], w2=key[63:32], w3=key[31:0];

    // Round 1 – Rcon 0x01
    wire [31:0] rot1 = {w3[23:0],w3[31:24]};
    wire [7:0] s1_0,s1_1,s1_2,s1_3;
    aes_sbox sb1_0(.in(rot1[31:24]),.out(s1_0)); aes_sbox sb1_1(.in(rot1[23:16]),.out(s1_1));
    aes_sbox sb1_2(.in(rot1[15:8]), .out(s1_2)); aes_sbox sb1_3(.in(rot1[7:0]),  .out(s1_3));
    wire [31:0] g1={s1_0,s1_1,s1_2,s1_3}^32'h01000000;
    wire [31:0] w4=w0^g1, w5=w1^w4, w6=w2^w5, w7=w3^w6;

    // Round 2 – Rcon 0x02
    wire [31:0] rot2 = {w7[23:0],w7[31:24]};
    wire [7:0] s2_0,s2_1,s2_2,s2_3;
    aes_sbox sb2_0(.in(rot2[31:24]),.out(s2_0)); aes_sbox sb2_1(.in(rot2[23:16]),.out(s2_1));
    aes_sbox sb2_2(.in(rot2[15:8]), .out(s2_2)); aes_sbox sb2_3(.in(rot2[7:0]),  .out(s2_3));
    wire [31:0] g2={s2_0,s2_1,s2_2,s2_3}^32'h02000000;
    wire [31:0] w8=w4^g2, w9=w5^w8, w10=w6^w9, w11=w7^w10;

    // Round 3 – Rcon 0x04
    wire [31:0] rot3 = {w11[23:0],w11[31:24]};
    wire [7:0] s3_0,s3_1,s3_2,s3_3;
    aes_sbox sb3_0(.in(rot3[31:24]),.out(s3_0)); aes_sbox sb3_1(.in(rot3[23:16]),.out(s3_1));
    aes_sbox sb3_2(.in(rot3[15:8]), .out(s3_2)); aes_sbox sb3_3(.in(rot3[7:0]),  .out(s3_3));
    wire [31:0] g3={s3_0,s3_1,s3_2,s3_3}^32'h04000000;
    wire [31:0] w12=w8^g3, w13=w9^w12, w14=w10^w13, w15=w11^w14;

    // Round 4 – Rcon 0x08
    wire [31:0] rot4 = {w15[23:0],w15[31:24]};
    wire [7:0] s4_0,s4_1,s4_2,s4_3;
    aes_sbox sb4_0(.in(rot4[31:24]),.out(s4_0)); aes_sbox sb4_1(.in(rot4[23:16]),.out(s4_1));
    aes_sbox sb4_2(.in(rot4[15:8]), .out(s4_2)); aes_sbox sb4_3(.in(rot4[7:0]),  .out(s4_3));
    wire [31:0] g4={s4_0,s4_1,s4_2,s4_3}^32'h08000000;
    wire [31:0] w16=w12^g4, w17=w13^w16, w18=w14^w17, w19=w15^w18;

    // Round 5 – Rcon 0x10
    wire [31:0] rot5 = {w19[23:0],w19[31:24]};
    wire [7:0] s5_0,s5_1,s5_2,s5_3;
    aes_sbox sb5_0(.in(rot5[31:24]),.out(s5_0)); aes_sbox sb5_1(.in(rot5[23:16]),.out(s5_1));
    aes_sbox sb5_2(.in(rot5[15:8]), .out(s5_2)); aes_sbox sb5_3(.in(rot5[7:0]),  .out(s5_3));
    wire [31:0] g5={s5_0,s5_1,s5_2,s5_3}^32'h10000000;
    wire [31:0] w20=w16^g5, w21=w17^w20, w22=w18^w21, w23=w19^w22;

    // Round 6 – Rcon 0x20
    wire [31:0] rot6 = {w23[23:0],w23[31:24]};
    wire [7:0] s6_0,s6_1,s6_2,s6_3;
    aes_sbox sb6_0(.in(rot6[31:24]),.out(s6_0)); aes_sbox sb6_1(.in(rot6[23:16]),.out(s6_1));
    aes_sbox sb6_2(.in(rot6[15:8]), .out(s6_2)); aes_sbox sb6_3(.in(rot6[7:0]),  .out(s6_3));
    wire [31:0] g6={s6_0,s6_1,s6_2,s6_3}^32'h20000000;
    wire [31:0] w24=w20^g6, w25=w21^w24, w26=w22^w25, w27=w23^w26;

    // Round 7 – Rcon 0x40
    wire [31:0] rot7 = {w27[23:0],w27[31:24]};
    wire [7:0] s7_0,s7_1,s7_2,s7_3;
    aes_sbox sb7_0(.in(rot7[31:24]),.out(s7_0)); aes_sbox sb7_1(.in(rot7[23:16]),.out(s7_1));
    aes_sbox sb7_2(.in(rot7[15:8]), .out(s7_2)); aes_sbox sb7_3(.in(rot7[7:0]),  .out(s7_3));
    wire [31:0] g7={s7_0,s7_1,s7_2,s7_3}^32'h40000000;
    wire [31:0] w28=w24^g7, w29=w25^w28, w30=w26^w29, w31=w27^w30;

    // Round 8 – Rcon 0x80
    wire [31:0] rot8 = {w31[23:0],w31[31:24]};
    wire [7:0] s8_0,s8_1,s8_2,s8_3;
    aes_sbox sb8_0(.in(rot8[31:24]),.out(s8_0)); aes_sbox sb8_1(.in(rot8[23:16]),.out(s8_1));
    aes_sbox sb8_2(.in(rot8[15:8]), .out(s8_2)); aes_sbox sb8_3(.in(rot8[7:0]),  .out(s8_3));
    wire [31:0] g8={s8_0,s8_1,s8_2,s8_3}^32'h80000000;
    wire [31:0] w32=w28^g8, w33=w29^w32, w34=w30^w33, w35=w31^w34;

    // Round 9 – Rcon 0x1b
    wire [31:0] rot9 = {w35[23:0],w35[31:24]};
    wire [7:0] s9_0,s9_1,s9_2,s9_3;
    aes_sbox sb9_0(.in(rot9[31:24]),.out(s9_0)); aes_sbox sb9_1(.in(rot9[23:16]),.out(s9_1));
    aes_sbox sb9_2(.in(rot9[15:8]), .out(s9_2)); aes_sbox sb9_3(.in(rot9[7:0]),  .out(s9_3));
    wire [31:0] g9={s9_0,s9_1,s9_2,s9_3}^32'h1b000000;
    wire [31:0] w36=w32^g9, w37=w33^w36, w38=w34^w37, w39=w35^w38;

    // Round 10 – Rcon 0x36
    wire [31:0] rot10 = {w39[23:0],w39[31:24]};
    wire [7:0] s10_0,s10_1,s10_2,s10_3;
    aes_sbox sb10_0(.in(rot10[31:24]),.out(s10_0)); aes_sbox sb10_1(.in(rot10[23:16]),.out(s10_1));
    aes_sbox sb10_2(.in(rot10[15:8]), .out(s10_2)); aes_sbox sb10_3(.in(rot10[7:0]),  .out(s10_3));
    wire [31:0] g10={s10_0,s10_1,s10_2,s10_3}^32'h36000000;
    wire [31:0] w40=w36^g10, w41=w37^w40, w42=w38^w41, w43=w39^w42;

    assign round_keys[0*128+:128]  = {w0,w1,w2,w3};
    assign round_keys[1*128+:128]  = {w4,w5,w6,w7};
    assign round_keys[2*128+:128]  = {w8,w9,w10,w11};
    assign round_keys[3*128+:128]  = {w12,w13,w14,w15};
    assign round_keys[4*128+:128]  = {w16,w17,w18,w19};
    assign round_keys[5*128+:128]  = {w20,w21,w22,w23};
    assign round_keys[6*128+:128]  = {w24,w25,w26,w27};
    assign round_keys[7*128+:128]  = {w28,w29,w30,w31};
    assign round_keys[8*128+:128]  = {w32,w33,w34,w35};
    assign round_keys[9*128+:128]  = {w36,w37,w38,w39};
    assign round_keys[10*128+:128] = {w40,w41,w42,w43};

// =========================================================================
end else if (KEY_W == 192) begin : g192
// =========================================================================
    wire [31:0] w0=key[191:160], w1=key[159:128], w2=key[127:96],
                w3=key[95:64],   w4=key[63:32],   w5=key[31:0];

    // Round 1 – i=6, Rcon 0x01
    wire [31:0] rot1={w5[23:0],w5[31:24]};
    wire [7:0] s1_0,s1_1,s1_2,s1_3;
    aes_sbox sb1_0(.in(rot1[31:24]),.out(s1_0)); aes_sbox sb1_1(.in(rot1[23:16]),.out(s1_1));
    aes_sbox sb1_2(.in(rot1[15:8]), .out(s1_2)); aes_sbox sb1_3(.in(rot1[7:0]),  .out(s1_3));
    wire [31:0] g1={s1_0,s1_1,s1_2,s1_3}^32'h01000000;
    wire [31:0] w6=w0^g1, w7=w1^w6, w8=w2^w7, w9=w3^w8, w10=w4^w9, w11=w5^w10;

    // Round 2 – i=12, Rcon 0x02
    wire [31:0] rot2={w11[23:0],w11[31:24]};
    wire [7:0] s2_0,s2_1,s2_2,s2_3;
    aes_sbox sb2_0(.in(rot2[31:24]),.out(s2_0)); aes_sbox sb2_1(.in(rot2[23:16]),.out(s2_1));
    aes_sbox sb2_2(.in(rot2[15:8]), .out(s2_2)); aes_sbox sb2_3(.in(rot2[7:0]),  .out(s2_3));
    wire [31:0] g2={s2_0,s2_1,s2_2,s2_3}^32'h02000000;
    wire [31:0] w12=w6^g2, w13=w7^w12, w14=w8^w13, w15=w9^w14, w16=w10^w15, w17=w11^w16;

    // Round 3 – i=18, Rcon 0x04
    wire [31:0] rot3={w17[23:0],w17[31:24]};
    wire [7:0] s3_0,s3_1,s3_2,s3_3;
    aes_sbox sb3_0(.in(rot3[31:24]),.out(s3_0)); aes_sbox sb3_1(.in(rot3[23:16]),.out(s3_1));
    aes_sbox sb3_2(.in(rot3[15:8]), .out(s3_2)); aes_sbox sb3_3(.in(rot3[7:0]),  .out(s3_3));
    wire [31:0] g3={s3_0,s3_1,s3_2,s3_3}^32'h04000000;
    wire [31:0] w18=w12^g3, w19=w13^w18, w20=w14^w19, w21=w15^w20, w22=w16^w21, w23=w17^w22;

    // Round 4 – i=24, Rcon 0x08
    wire [31:0] rot4={w23[23:0],w23[31:24]};
    wire [7:0] s4_0,s4_1,s4_2,s4_3;
    aes_sbox sb4_0(.in(rot4[31:24]),.out(s4_0)); aes_sbox sb4_1(.in(rot4[23:16]),.out(s4_1));
    aes_sbox sb4_2(.in(rot4[15:8]), .out(s4_2)); aes_sbox sb4_3(.in(rot4[7:0]),  .out(s4_3));
    wire [31:0] g4={s4_0,s4_1,s4_2,s4_3}^32'h08000000;
    wire [31:0] w24=w18^g4, w25=w19^w24, w26=w20^w25, w27=w21^w26, w28=w22^w27, w29=w23^w28;

    // Round 5 – i=30, Rcon 0x10
    wire [31:0] rot5={w29[23:0],w29[31:24]};
    wire [7:0] s5_0,s5_1,s5_2,s5_3;
    aes_sbox sb5_0(.in(rot5[31:24]),.out(s5_0)); aes_sbox sb5_1(.in(rot5[23:16]),.out(s5_1));
    aes_sbox sb5_2(.in(rot5[15:8]), .out(s5_2)); aes_sbox sb5_3(.in(rot5[7:0]),  .out(s5_3));
    wire [31:0] g5={s5_0,s5_1,s5_2,s5_3}^32'h10000000;
    wire [31:0] w30=w24^g5, w31=w25^w30, w32=w26^w31, w33=w27^w32, w34=w28^w33, w35=w29^w34;

    // Round 6 – i=36, Rcon 0x20
    wire [31:0] rot6={w35[23:0],w35[31:24]};
    wire [7:0] s6_0,s6_1,s6_2,s6_3;
    aes_sbox sb6_0(.in(rot6[31:24]),.out(s6_0)); aes_sbox sb6_1(.in(rot6[23:16]),.out(s6_1));
    aes_sbox sb6_2(.in(rot6[15:8]), .out(s6_2)); aes_sbox sb6_3(.in(rot6[7:0]),  .out(s6_3));
    wire [31:0] g6={s6_0,s6_1,s6_2,s6_3}^32'h20000000;
    wire [31:0] w36=w30^g6, w37=w31^w36, w38=w32^w37, w39=w33^w38, w40=w34^w39, w41=w35^w40;

    // Round 7 – i=42, Rcon 0x40
    wire [31:0] rot7={w41[23:0],w41[31:24]};
    wire [7:0] s7_0,s7_1,s7_2,s7_3;
    aes_sbox sb7_0(.in(rot7[31:24]),.out(s7_0)); aes_sbox sb7_1(.in(rot7[23:16]),.out(s7_1));
    aes_sbox sb7_2(.in(rot7[15:8]), .out(s7_2)); aes_sbox sb7_3(.in(rot7[7:0]),  .out(s7_3));
    wire [31:0] g7={s7_0,s7_1,s7_2,s7_3}^32'h40000000;
    wire [31:0] w42=w36^g7, w43=w37^w42, w44=w38^w43, w45=w39^w44, w46=w40^w45, w47=w41^w46;

    // Round 8 – i=48, Rcon 0x80
    wire [31:0] rot8={w47[23:0],w47[31:24]};
    wire [7:0] s8_0,s8_1,s8_2,s8_3;
    aes_sbox sb8_0(.in(rot8[31:24]),.out(s8_0)); aes_sbox sb8_1(.in(rot8[23:16]),.out(s8_1));
    aes_sbox sb8_2(.in(rot8[15:8]), .out(s8_2)); aes_sbox sb8_3(.in(rot8[7:0]),  .out(s8_3));
    wire [31:0] g8={s8_0,s8_1,s8_2,s8_3}^32'h80000000;
    wire [31:0] w48=w42^g8, w49=w43^w48, w50=w44^w49, w51=w45^w50;

    assign round_keys[0*128+:128]  = {w0,w1,w2,w3};
    assign round_keys[1*128+:128]  = {w4,w5,w6,w7};
    assign round_keys[2*128+:128]  = {w8,w9,w10,w11};
    assign round_keys[3*128+:128]  = {w12,w13,w14,w15};
    assign round_keys[4*128+:128]  = {w16,w17,w18,w19};
    assign round_keys[5*128+:128]  = {w20,w21,w22,w23};
    assign round_keys[6*128+:128]  = {w24,w25,w26,w27};
    assign round_keys[7*128+:128]  = {w28,w29,w30,w31};
    assign round_keys[8*128+:128]  = {w32,w33,w34,w35};
    assign round_keys[9*128+:128]  = {w36,w37,w38,w39};
    assign round_keys[10*128+:128] = {w40,w41,w42,w43};
    assign round_keys[11*128+:128] = {w44,w45,w46,w47};
    assign round_keys[12*128+:128] = {w48,w49,w50,w51};

// =========================================================================
end else begin : g256
// =========================================================================
    wire [31:0] w0=key[255:224], w1=key[223:192], w2=key[191:160], w3=key[159:128],
                w4=key[127:96],  w5=key[95:64],   w6=key[63:32],   w7=key[31:0];

    // Round 1a – i=8, Rcon 0x01
    wire [31:0] rot1={w7[23:0],w7[31:24]};
    wire [7:0] s1_0,s1_1,s1_2,s1_3;
    aes_sbox sb1_0(.in(rot1[31:24]),.out(s1_0)); aes_sbox sb1_1(.in(rot1[23:16]),.out(s1_1));
    aes_sbox sb1_2(.in(rot1[15:8]), .out(s1_2)); aes_sbox sb1_3(.in(rot1[7:0]),  .out(s1_3));
    wire [31:0] g1={s1_0,s1_1,s1_2,s1_3}^32'h01000000;
    wire [31:0] w8=w0^g1, w9=w1^w8, w10=w2^w9, w11=w3^w10;

    // Round 1b – i=12, SubWord only (no rotation)
    wire [7:0] sw1_0,sw1_1,sw1_2,sw1_3;
    aes_sbox sw1b_0(.in(w11[31:24]),.out(sw1_0)); aes_sbox sw1b_1(.in(w11[23:16]),.out(sw1_1));
    aes_sbox sw1b_2(.in(w11[15:8]), .out(sw1_2)); aes_sbox sw1b_3(.in(w11[7:0]),  .out(sw1_3));
    wire [31:0] sw1={sw1_0,sw1_1,sw1_2,sw1_3};
    wire [31:0] w12=w4^sw1, w13=w5^w12, w14=w6^w13, w15=w7^w14;

    // Round 2a – i=16, Rcon 0x02
    wire [31:0] rot2={w15[23:0],w15[31:24]};
    wire [7:0] s2_0,s2_1,s2_2,s2_3;
    aes_sbox sb2_0(.in(rot2[31:24]),.out(s2_0)); aes_sbox sb2_1(.in(rot2[23:16]),.out(s2_1));
    aes_sbox sb2_2(.in(rot2[15:8]), .out(s2_2)); aes_sbox sb2_3(.in(rot2[7:0]),  .out(s2_3));
    wire [31:0] g2={s2_0,s2_1,s2_2,s2_3}^32'h02000000;
    wire [31:0] w16=w8^g2, w17=w9^w16, w18=w10^w17, w19=w11^w18;

    // Round 2b – i=20, SubWord only
    wire [7:0] sw2_0,sw2_1,sw2_2,sw2_3;
    aes_sbox sw2b_0(.in(w19[31:24]),.out(sw2_0)); aes_sbox sw2b_1(.in(w19[23:16]),.out(sw2_1));
    aes_sbox sw2b_2(.in(w19[15:8]), .out(sw2_2)); aes_sbox sw2b_3(.in(w19[7:0]),  .out(sw2_3));
    wire [31:0] sw2={sw2_0,sw2_1,sw2_2,sw2_3};
    wire [31:0] w20=w12^sw2, w21=w13^w20, w22=w14^w21, w23=w15^w22;

    // Round 3a – i=24, Rcon 0x04
    wire [31:0] rot3={w23[23:0],w23[31:24]};
    wire [7:0] s3_0,s3_1,s3_2,s3_3;
    aes_sbox sb3_0(.in(rot3[31:24]),.out(s3_0)); aes_sbox sb3_1(.in(rot3[23:16]),.out(s3_1));
    aes_sbox sb3_2(.in(rot3[15:8]), .out(s3_2)); aes_sbox sb3_3(.in(rot3[7:0]),  .out(s3_3));
    wire [31:0] g3={s3_0,s3_1,s3_2,s3_3}^32'h04000000;
    wire [31:0] w24=w16^g3, w25=w17^w24, w26=w18^w25, w27=w19^w26;

    // Round 3b – i=28, SubWord only
    wire [7:0] sw3_0,sw3_1,sw3_2,sw3_3;
    aes_sbox sw3b_0(.in(w27[31:24]),.out(sw3_0)); aes_sbox sw3b_1(.in(w27[23:16]),.out(sw3_1));
    aes_sbox sw3b_2(.in(w27[15:8]), .out(sw3_2)); aes_sbox sw3b_3(.in(w27[7:0]),  .out(sw3_3));
    wire [31:0] sw3={sw3_0,sw3_1,sw3_2,sw3_3};
    wire [31:0] w28=w20^sw3, w29=w21^w28, w30=w22^w29, w31=w23^w30;

    // Round 4a – i=32, Rcon 0x08
    wire [31:0] rot4={w31[23:0],w31[31:24]};
    wire [7:0] s4_0,s4_1,s4_2,s4_3;
    aes_sbox sb4_0(.in(rot4[31:24]),.out(s4_0)); aes_sbox sb4_1(.in(rot4[23:16]),.out(s4_1));
    aes_sbox sb4_2(.in(rot4[15:8]), .out(s4_2)); aes_sbox sb4_3(.in(rot4[7:0]),  .out(s4_3));
    wire [31:0] g4={s4_0,s4_1,s4_2,s4_3}^32'h08000000;
    wire [31:0] w32=w24^g4, w33=w25^w32, w34=w26^w33, w35=w27^w34;

    // Round 4b – i=36, SubWord only
    wire [7:0] sw4_0,sw4_1,sw4_2,sw4_3;
    aes_sbox sw4b_0(.in(w35[31:24]),.out(sw4_0)); aes_sbox sw4b_1(.in(w35[23:16]),.out(sw4_1));
    aes_sbox sw4b_2(.in(w35[15:8]), .out(sw4_2)); aes_sbox sw4b_3(.in(w35[7:0]),  .out(sw4_3));
    wire [31:0] sw4={sw4_0,sw4_1,sw4_2,sw4_3};
    wire [31:0] w36=w28^sw4, w37=w29^w36, w38=w30^w37, w39=w31^w38;

    // Round 5a – i=40, Rcon 0x10
    wire [31:0] rot5={w39[23:0],w39[31:24]};
    wire [7:0] s5_0,s5_1,s5_2,s5_3;
    aes_sbox sb5_0(.in(rot5[31:24]),.out(s5_0)); aes_sbox sb5_1(.in(rot5[23:16]),.out(s5_1));
    aes_sbox sb5_2(.in(rot5[15:8]), .out(s5_2)); aes_sbox sb5_3(.in(rot5[7:0]),  .out(s5_3));
    wire [31:0] g5={s5_0,s5_1,s5_2,s5_3}^32'h10000000;
    wire [31:0] w40=w32^g5, w41=w33^w40, w42=w34^w41, w43=w35^w42;

    // Round 5b – i=44, SubWord only
    wire [7:0] sw5_0,sw5_1,sw5_2,sw5_3;
    aes_sbox sw5b_0(.in(w43[31:24]),.out(sw5_0)); aes_sbox sw5b_1(.in(w43[23:16]),.out(sw5_1));
    aes_sbox sw5b_2(.in(w43[15:8]), .out(sw5_2)); aes_sbox sw5b_3(.in(w43[7:0]),  .out(sw5_3));
    wire [31:0] sw5={sw5_0,sw5_1,sw5_2,sw5_3};
    wire [31:0] w44=w36^sw5, w45=w37^w44, w46=w38^w45, w47=w39^w46;

    // Round 6a – i=48, Rcon 0x20
    wire [31:0] rot6={w47[23:0],w47[31:24]};
    wire [7:0] s6_0,s6_1,s6_2,s6_3;
    aes_sbox sb6_0(.in(rot6[31:24]),.out(s6_0)); aes_sbox sb6_1(.in(rot6[23:16]),.out(s6_1));
    aes_sbox sb6_2(.in(rot6[15:8]), .out(s6_2)); aes_sbox sb6_3(.in(rot6[7:0]),  .out(s6_3));
    wire [31:0] g6={s6_0,s6_1,s6_2,s6_3}^32'h20000000;
    wire [31:0] w48=w40^g6, w49=w41^w48, w50=w42^w49, w51=w43^w50;

    // Round 6b – i=52, SubWord only
    wire [7:0] sw6_0,sw6_1,sw6_2,sw6_3;
    aes_sbox sw6b_0(.in(w51[31:24]),.out(sw6_0)); aes_sbox sw6b_1(.in(w51[23:16]),.out(sw6_1));
    aes_sbox sw6b_2(.in(w51[15:8]), .out(sw6_2)); aes_sbox sw6b_3(.in(w51[7:0]),  .out(sw6_3));
    wire [31:0] sw6={sw6_0,sw6_1,sw6_2,sw6_3};
    wire [31:0] w52=w44^sw6, w53=w45^w52, w54=w46^w53, w55=w47^w54;

    // Round 7a – i=56, Rcon 0x40
    wire [31:0] rot7={w55[23:0],w55[31:24]};
    wire [7:0] s7_0,s7_1,s7_2,s7_3;
    aes_sbox sb7_0(.in(rot7[31:24]),.out(s7_0)); aes_sbox sb7_1(.in(rot7[23:16]),.out(s7_1));
    aes_sbox sb7_2(.in(rot7[15:8]), .out(s7_2)); aes_sbox sb7_3(.in(rot7[7:0]),  .out(s7_3));
    wire [31:0] g7={s7_0,s7_1,s7_2,s7_3}^32'h40000000;
    wire [31:0] w56=w48^g7, w57=w49^w56, w58=w50^w57, w59=w51^w58;

    assign round_keys[0*128+:128]  = {w0,w1,w2,w3};
    assign round_keys[1*128+:128]  = {w4,w5,w6,w7};
    assign round_keys[2*128+:128]  = {w8,w9,w10,w11};
    assign round_keys[3*128+:128]  = {w12,w13,w14,w15};
    assign round_keys[4*128+:128]  = {w16,w17,w18,w19};
    assign round_keys[5*128+:128]  = {w20,w21,w22,w23};
    assign round_keys[6*128+:128]  = {w24,w25,w26,w27};
    assign round_keys[7*128+:128]  = {w28,w29,w30,w31};
    assign round_keys[8*128+:128]  = {w32,w33,w34,w35};
    assign round_keys[9*128+:128]  = {w36,w37,w38,w39};
    assign round_keys[10*128+:128] = {w40,w41,w42,w43};
    assign round_keys[11*128+:128] = {w44,w45,w46,w47};
    assign round_keys[12*128+:128] = {w48,w49,w50,w51};
    assign round_keys[13*128+:128] = {w52,w53,w54,w55};
    assign round_keys[14*128+:128] = {w56,w57,w58,w59};

end
endgenerate
endmodule
