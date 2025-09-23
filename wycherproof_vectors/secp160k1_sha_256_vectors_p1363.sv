`ifndef WYCHERPROOF_SECP160K1_SHA256_P1363_SV
`define WYCHERPROOF_SECP160K1_SHA256_P1363_SV
typedef struct packed {
  int            tc_id;
  bit            valid;   // Wycheproof: valid/acceptable=1, else=0
  logic [511:0]  hash;    // 固定宣告 512 bits
  logic [527:0]  x;       // 固定宣告 528 bits
  logic [527:0]  y;       // 固定宣告 528 bits
  logic [527:0]  r;       // 固定宣告 528 bits
  logic [527:0]  s;       // 固定宣告 528 bits
} ecdsa_vector_secp160k1_sha256_p1363;

localparam int TEST_VECTORS_SECP160K1_SHA256_P1363_NUM = 3;

ecdsa_vector_secp160k1_sha256_p1363 test_vectors_secp160k1_sha256_p1363 [] = '{
  '{119, 1'b1, 256'hbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023, 160'h012a78f3ceb2c5606f824b90b4151a7cd788c3c8, 160'h6216521c8b038e7080bb5601ac8b49e96826368b, 8'h03, 8'h01},  // lens: hash=256b(32B), x=160b(20B), y=160b(20B), r=8b(1B), s=8b(1B)
  '{121, 1'b1, 256'hbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023, 168'h00cee7f5abdb03bb603a30a7a781d2249708931e28, 168'h00f459dfe37fef1cc13d5832452381cc179e708728, 8'h03, 8'h03},  // lens: hash=256b(32B), x=168b(21B), y=168b(21B), r=8b(1B), s=8b(1B)
  '{123, 1'b1, 256'hbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023, 160'h48c7400e22d2ef7354b820eb662105e1b6e44a60, 168'h00a329f8bd69afd5aa91d4e18d3cfa2428930dee68, 8'h03, 8'h04}  // lens: hash=256b(32B), x=160b(20B), y=168b(21B), r=8b(1B), s=8b(1B)
};
`endif // WYCHERPROOF_SECP160K1_SHA256_P1363_SV
