#include <iostream>
#include <memory>

#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"

using namespace std;
using namespace libsnark;

/**
 * In this example, we show a very simple zero-knowledge proving procedure
 * using the r1cs ppzksnark proof system.
 */

const char *sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"; // SHA256(abc)

int main() {
  using ppT = default_r1cs_ppzksnark_pp; // Use the default public parameters
  using FieldT = ppT::Fp_type; // ppT is a specification for a collection of types, among which Fp_type is the base field

  ppT::init_public_params(); // Initialize the libsnark

  const auto one = FieldT::one(); // constant
  const auto zero = FieldT::zero(); // constant

  /*********************************/
  /* Everybody: Design the circuit */
  /*********************************/
  protoboard<FieldT> pb; // The board to allocate gadgets

  pb_variable_array<FieldT> A; // The input wires (anchor) for A
  pb_variable_array<FieldT> B; // The input wires (anchor) for B

	pb_variable_array<FieldT> length_padding;
	digest_variable<FieldT> intermediate(pb, 256, "intermediate");

	A.allocate(pb, 256, "A");
	B.allocate(pb, 24, "B");
	length_padding.allocate(pb, 488, "padding");

	pb.val(length_padding[0]) = one; // length padding = 100000 ... 000<length binary expression>
	pb.val(length_padding[483]) = one; // 24 = 11000
	pb.val(length_padding[484]) = one;

  // C = SHA256(B)
  digest_variable<FieldT> C(pb, 256, "D");

	block_variable<FieldT> block(pb, {B, length_padding}, "block"); // block: B||length_padding

  /* Connect the anchors by a sha256 gadget */
	pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);
  sha256_compression_function_gadget<FieldT> sha256(pb, IV, block.bits, C, "sha256"); // C = SHA256Compress(block)

  /* Set the first 256 of anchors as public inputs. */
  pb.set_input_sizes(256);

  sha256.generate_r1cs_constraints();

	/* Add constraint that A and D are equal */
	for(int i = 0; i < 256; i++)
		pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1,A[i],C.bits[i]), "A=C");

  /* Finally, extract the resulting R1CS constraint system */
  auto cs = pb.get_constraint_system(); 
  /***************************************/
  /* Trusted Third Party: Key generation */
  /***************************************/
  auto keypair = r1cs_ppzksnark_generator<ppT>(pb.get_constraint_system());

  /**************************************************/
  /* Prover: Fill in both inputs and generate proof */
  /**************************************************/
  for (size_t i = 0; i < 256; i++) {
		char bits = sha[i/4];
		if(bits >= '0' && bits <= '9') bits = bits-'0';
		else if(bits >= 'a' && bits <= 'f') bits = bits-'a'+10;
		int bit = (bits>>(3-i%4))&1;
		pb.val(A[i]) = bit? one: zero;
	}
	// B = 011000010110001001100011
  pb.val(B[1]) = one;
  pb.val(B[2]) = one;
  pb.val(B[7]) = one;
  pb.val(B[9]) = one;
  pb.val(B[10]) = one;
  pb.val(B[14]) = one;
  pb.val(B[17]) = one;
  pb.val(B[18]) = one;
  pb.val(B[22]) = one;
  pb.val(B[23]) = one;

  /* We just set the value of the input anchors,
   * now execute this function to function the gadget and fill in the other
   * anchors */
  sha256.generate_r1cs_witness();

  auto pi = pb.primary_input();
  auto ai = pb.auxiliary_input();
  auto proof = r1cs_ppzksnark_prover<ppT>(keypair.pk,pi,ai);

  /********************************************/
  /* Verifier: fill in only the public inputs */
  /********************************************/
  for (size_t i = 0; i < 256; i++) {
		char bits = sha[i/4];
		if(bits >= '0' && bits <= '9') bits = bits-'0';
		else if(bits >= 'a' && bits <= 'f') bits = bits-'a'+10;
		int bit = (bits>>(3-i%4))&1;
		pb.val(A[i]) = bit? one: zero;
	}
  pi = pb.primary_input();

  if(r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk,pi,proof)) {
    cout << "Verified!" << endl;
  } else {
    cout << "Failed to verify!" << endl;
  }

  return 0;
}
