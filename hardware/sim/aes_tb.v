// AES-128/192/256 pipelined encrypt+decrypt testbench
// Vectors from FIPS 197 Appendix B and NIST CAVS
`timescale 1ns/1ps
module aes_tb;

reg clk, rst;
initial clk = 0;
always #5 clk = ~clk;

// -------------------------------------------------------------------------
// AES-128
// -------------------------------------------------------------------------
// Key:        2b7e151628aed2a6abf7158809cf4f3c
// Plaintext:  3243f6a8885a308d313198a2e0370734
// Ciphertext: 3925841d02dc09fbdc118597196a0b32
localparam [127:0] KEY128  = 128'h2b7e151628aed2a6abf7158809cf4f3c;
localparam [127:0] PT128   = 128'h3243f6a8885a308d313198a2e0370734;
localparam [127:0] CT128   = 128'h3925841d02dc09fbdc118597196a0b32;

reg        enc128_vin;
reg [127:0] enc128_pt;
wire        enc128_vout;
wire [127:0] enc128_ct;

aes_encrypt #(.KEY_W(128)) u_enc128 (
    .clk(clk), .rst(rst),
    .valid_in(enc128_vin), .plaintext(enc128_pt), .key(KEY128),
    .valid_out(enc128_vout), .ciphertext(enc128_ct)
);

reg        dec128_vin;
reg [127:0] dec128_ct;
wire        dec128_vout;
wire [127:0] dec128_pt;

aes_decrypt #(.KEY_W(128)) u_dec128 (
    .clk(clk), .rst(rst),
    .valid_in(dec128_vin), .ciphertext(dec128_ct), .key(KEY128),
    .valid_out(dec128_vout), .plaintext(dec128_pt)
);

// -------------------------------------------------------------------------
// AES-192
// -------------------------------------------------------------------------
// Key:        8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b
// Plaintext:  6bc1bee22e409f96e93d7e117393172a
// Ciphertext: bd334f1d6e45f25ff712a214571fa5cc
localparam [191:0] KEY192  = 192'h8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b;
localparam [127:0] PT192   = 128'h6bc1bee22e409f96e93d7e117393172a;
localparam [127:0] CT192   = 128'hbd334f1d6e45f25ff712a214571fa5cc;

reg        enc192_vin;
reg [127:0] enc192_pt;
wire        enc192_vout;
wire [127:0] enc192_ct;

aes_encrypt #(.KEY_W(192)) u_enc192 (
    .clk(clk), .rst(rst),
    .valid_in(enc192_vin), .plaintext(enc192_pt), .key(KEY192),
    .valid_out(enc192_vout), .ciphertext(enc192_ct)
);

reg        dec192_vin;
reg [127:0] dec192_ct;
wire        dec192_vout;
wire [127:0] dec192_pt;

aes_decrypt #(.KEY_W(192)) u_dec192 (
    .clk(clk), .rst(rst),
    .valid_in(dec192_vin), .ciphertext(dec192_ct), .key(KEY192),
    .valid_out(dec192_vout), .plaintext(dec192_pt)
);

// -------------------------------------------------------------------------
// AES-256
// -------------------------------------------------------------------------
// Key:        603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4
// Plaintext:  6bc1bee22e409f96e93d7e117393172a
// Ciphertext: f3eed1bdb5d2a03c064b5a7e3db181f8
localparam [255:0] KEY256  = 256'h603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4;
localparam [127:0] PT256   = 128'h6bc1bee22e409f96e93d7e117393172a;
localparam [127:0] CT256   = 128'hf3eed1bdb5d2a03c064b5a7e3db181f8;

reg        enc256_vin;
reg [127:0] enc256_pt;
wire        enc256_vout;
wire [127:0] enc256_ct;

aes_encrypt #(.KEY_W(256)) u_enc256 (
    .clk(clk), .rst(rst),
    .valid_in(enc256_vin), .plaintext(enc256_pt), .key(KEY256),
    .valid_out(enc256_vout), .ciphertext(enc256_ct)
);

reg        dec256_vin;
reg [127:0] dec256_ct;
wire        dec256_vout;
wire [127:0] dec256_pt;

aes_decrypt #(.KEY_W(256)) u_dec256 (
    .clk(clk), .rst(rst),
    .valid_in(dec256_vin), .ciphertext(dec256_ct), .key(KEY256),
    .valid_out(dec256_vout), .plaintext(dec256_pt)
);

// -------------------------------------------------------------------------
// Stimulus + checking
// -------------------------------------------------------------------------
integer fail = 0;

task check;
    input [127:0] got, exp;
    input [63:0]  label; // not printed, just for wave annotation
    begin
        if (got !== exp) begin
            $display("FAIL: got %h  expected %h", got, exp);
            fail = fail + 1;
        end
    end
endtask

initial begin
    rst = 1;
    enc128_vin = 0; enc128_pt = 0;
    dec128_vin = 0; dec128_ct = 0;
    enc192_vin = 0; enc192_pt = 0;
    dec192_vin = 0; dec192_ct = 0;
    enc256_vin = 0; enc256_pt = 0;
    dec256_vin = 0; dec256_ct = 0;
    repeat(4) @(posedge clk);
    rst = 0;
    @(posedge clk);

    // Drive all six pipelines simultaneously
    enc128_pt = PT128;  enc128_vin = 1;
    dec128_ct = CT128;  dec128_vin = 1;
    enc192_pt = PT192;  enc192_vin = 1;
    dec192_ct = CT192;  dec192_vin = 1;
    enc256_pt = PT256;  enc256_vin = 1;
    dec256_ct = CT256;  dec256_vin = 1;
    @(posedge clk); // inputs captured into stage-0 registers
    enc128_vin = 0; dec128_vin = 0;
    enc192_vin = 0; dec192_vin = 0;
    enc256_vin = 0; dec256_vin = 0;

    // AES-128: Nr=10 → valid_out fires after 11 more posedges (Nr+1)
    repeat(11) @(posedge clk);
    if (enc128_vout) check(enc128_ct, CT128, "enc128");
    else begin $display("FAIL: enc128 valid not asserted"); fail=fail+1; end
    if (dec128_vout) check(dec128_pt, PT128, "dec128");
    else begin $display("FAIL: dec128 valid not asserted"); fail=fail+1; end

    // AES-192: Nr=12 → 2 more posedges (13 total)
    repeat(2) @(posedge clk);
    if (enc192_vout) check(enc192_ct, CT192, "enc192");
    else begin $display("FAIL: enc192 valid not asserted"); fail=fail+1; end
    if (dec192_vout) check(dec192_pt, PT192, "dec192");
    else begin $display("FAIL: dec192 valid not asserted"); fail=fail+1; end

    // AES-256: Nr=14 → 2 more posedges (15 total)
    repeat(2) @(posedge clk);
    if (enc256_vout) check(enc256_ct, CT256, "enc256");
    else begin $display("FAIL: enc256 valid not asserted"); fail=fail+1; end
    if (dec256_vout) check(dec256_pt, PT256, "dec256");
    else begin $display("FAIL: dec256 valid not asserted"); fail=fail+1; end

    if (fail == 0)
        $display("PASS – AES-128/192/256 encrypt+decrypt all correct");
    else
        $display("FAIL – %0d check(s) failed", fail);

    $finish;
end

endmodule
