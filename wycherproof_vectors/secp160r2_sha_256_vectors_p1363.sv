`ifndef WYCHERPROOF_SECP160R2_SHA256_P1363_SV
`define WYCHERPROOF_SECP160R2_SHA256_P1363_SV
typedef struct packed {
  int            tc_id;
  bit            valid;   // Wycheproof: valid/acceptable=1, else=0
  logic [511:0]  hash;    // 固定宣告 512 bits
  logic [527:0]  x;       // 固定宣告 528 bits
  logic [527:0]  y;       // 固定宣告 528 bits
  logic [527:0]  r;       // 固定宣告 528 bits
  logic [527:0]  s;       // 固定宣告 528 bits
} ecdsa_vector_secp160r2_sha256_p1363;

localparam int TEST_VECTORS_SECP160R2_SHA256_P1363_NUM = 4;

ecdsa_vector_secp160r2_sha256_p1363 test_vectors_secp160r2_sha256_p1363 [] = '{
  '{116, 1'b1, 256'hbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023, 168'h00fa19aff61dccb4982a520c4a844210d88245e643, 168'h00cad5c9f87432f65dc9609b50ae80da751a86bd32, 80'h351ee786a819f3a1f4f5, 80'h351ee786a819f3a1f4f4},  // lens: hash=256b(32B), x=168b(21B), y=168b(21B), r=80b(10B), s=80b(10B)
  '{120, 1'b1, 256'hbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023, 160'h74151122fd301dec9139e1277de1063810fcf9c6, 168'h00f1797e4233303f7279e8bff017466a2963da7b53, 8'h03, 8'h01},  // lens: hash=256b(32B), x=160b(20B), y=168b(21B), r=8b(1B), s=8b(1B)
  '{122, 1'b1, 256'hbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023, 168'h00af1ee8e681b5db8479ad6d2c3cce1bb6da8c87c3, 160'h427c7f8dc4de05c78a0ffcf5412ef343bb137e12, 8'h03, 8'h03},  // lens: hash=256b(32B), x=168b(21B), y=160b(20B), r=8b(1B), s=8b(1B)
  '{124, 1'b1, 256'hbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023, 168'h00bebde6a1518a38bcb7fecfb6e70d92ec5de9e2fc, 168'h00931816f21cd2ff7c7317aeccf50a994a6fb44c71, 8'h03, 8'h04}  // lens: hash=256b(32B), x=168b(21B), y=168b(21B), r=8b(1B), s=8b(1B)
};
`endif // WYCHERPROOF_SECP160R2_SHA256_P1363_SV
