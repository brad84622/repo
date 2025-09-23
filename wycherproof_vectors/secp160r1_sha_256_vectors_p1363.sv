`ifndef WYCHERPROOF_SECP160R1_SHA256_P1363_SV
`define WYCHERPROOF_SECP160R1_SHA256_P1363_SV
typedef struct packed {
  int            tc_id;
  bit            valid;   // Wycheproof: valid/acceptable=1, else=0
  logic [511:0]  hash;    // 固定宣告 512 bits
  logic [527:0]  x;       // 固定宣告 528 bits
  logic [527:0]  y;       // 固定宣告 528 bits
  logic [527:0]  r;       // 固定宣告 528 bits
  logic [527:0]  s;       // 固定宣告 528 bits
} ecdsa_vector_secp160r1_sha256_p1363;

localparam int TEST_VECTORS_SECP160R1_SHA256_P1363_NUM = 5;

ecdsa_vector_secp160r1_sha256_p1363 test_vectors_secp160r1_sha256_p1363 [] = '{
  '{116, 1'b1, 256'hbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023, 168'h00b005b80cb0733576bd27520bf7ac44f28e733718, 160'h09738b9aeb21252938e9a5fa885a4bfa3705e084, 88'h01f4c8f927aed44a752255, 88'h01f4c8f927aed44a752254},  // lens: hash=256b(32B), x=168b(21B), y=160b(20B), r=88b(11B), s=88b(11B)
  '{120, 1'b1, 256'hbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023, 168'h00b3e8857e27393fb609bb7e4d42bb612704d9eef2, 160'h668439313310a849e17faca660f5f5346e11c1a9, 8'h04, 8'h01},  // lens: hash=256b(32B), x=168b(21B), y=160b(20B), r=8b(1B), s=8b(1B)
  '{122, 1'b1, 256'hbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023, 160'h1b66bc474c8220de08f3db0fdc984b008828ff5d, 168'h00f94509a6596f822f62580acc988bf962ef9e32b8, 8'h04, 8'h03},  // lens: hash=256b(32B), x=160b(20B), y=168b(21B), r=8b(1B), s=8b(1B)
  '{124, 1'b1, 256'hbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023, 168'h008ac14539432e062ff2b1f6086926bfc87e342e98, 168'h00bdc182b2ec96ac855f1057cd99731a054067a153, 8'h04, 8'h04},  // lens: hash=256b(32B), x=168b(21B), y=168b(21B), r=8b(1B), s=8b(1B)
  '{126, 1'b1, 256'hbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023, 160'h4a5c77d11ddaa568733d8a6cb79b497e6a644944, 160'h339c2514eda2e275ceffb9a7fc4c8d0470b37638, 8'h04, 8'h05}  // lens: hash=256b(32B), x=160b(20B), y=160b(20B), r=8b(1B), s=8b(1B)
};
`endif // WYCHERPROOF_SECP160R1_SHA256_P1363_SV
