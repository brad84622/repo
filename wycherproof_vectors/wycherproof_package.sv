`ifndef WYCHERPROOF_PACKAGE_SV
`define WYCHERPROOF_PACKAGE_SV
package wycherproof_pkg;

  `include "secp256r1_sha_256_vectors.sv"
  `include "secp256r1_sha_256_vectors.sv"
  `include "secp256r1_sha3_256_vectors.sv"
  `include "secp256r1_sha3_512_vectors.sv"
  `include "secp256r1_sha_512_vectors.sv"
  `include "secp256r1_sha_512_vectors.sv"
  `include "secp384r1_sha_384_vectors.sv"
  `include "secp384r1_sha_384_vectors.sv"
  `include "secp384r1_sha3_384_vectors.sv"
  `include "secp384r1_sha3_512_vectors.sv"
  `include "secp384r1_sha_512_vectors.sv"
  `include "secp384r1_sha_512_vectors.sv"
  `include "secp521r1_sha3_512_vectors.sv"
  `include "secp521r1_sha_512_vectors.sv"
  `include "secp521r1_sha_512_vectors.sv"

endpackage : wycherproof_pkg
`endif // WYCHERPROOF_PACKAGE_SV
