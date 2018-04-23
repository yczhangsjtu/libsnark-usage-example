#include <iostream>
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"

using namespace std;
using namespace libsnark;

/**
 * In this example, we show a very simple zero-knowledge proving procedure
 * using the r1cs ppzksnark proof system.
 *
 * In this simple example, we show that given vector x = (1,1,1,1,1,1,1,1,1,1)
 * we know another vector a such that: inner_product(x,a)=0
 * (yes, I know this is a trivial problem, but let's just focus on the ideas)
 */

int main() {
  using ppT = default_r1cs_ppzksnark_pp; // Use the default public parameters
  using FieldT = ppT::Fp_type; // ppT is a specification for a collection of types, among which Fp_type is the base field
  // const auto one = FieldT::one(); // constant
  // std::vector<FieldT> public_input{one,one,one,one,one,one,one,one,one,one}; // x = (1,1,1,1,1,1,1,1,1,1)
  // std::vector<FieldT> secret_input{one,-one,one,-one,one,-one,one,-one,one,-one}; // our secret a such that <x,a> = 0

  /*********************************/
  /* Everybody: Design the circuit */
  /*********************************/
  protoboard<FieldT> pb; // The board to allocate gadgets
  digest_variable<FieldT> A(pb, 256, "A"); // The input wires (anchor) for x
  digest_variable<FieldT> B(pb, 256, "B"); // The input wires (anchor) for a
  digest_variable<FieldT> res(pb, 256, "res"); // The output wire (anchor)

  ppT::init_public_params(); // Initialize the libsnark
  /* Connect the anchors by a sha256 gadget, specifying the
   * relationship for the anchors (A,B and res) to satisfy.
   * Note that this gadget introduces a lot more (to be accurate, 9) anchors
   * on the protoboard. Now there are 30 anchors in total. */
  sha256_two_to_one_hash_gadget<FieldT> sha256(pb, A, B, res, "sha256");

  /* Set the first **dimension** number of anchors as public inputs. */
  pb.set_input_sizes(256);
  /* Compute R1CS constraints resulted from the inner product gadget. */
  sha256.generate_r1cs_constraints();
  /* Finally, extract the resulting R1CS constraint system */
  auto cs = pb.get_constraint_system();

  /***************************************/
  /* Trusted Third Party: Key generation */
  /***************************************/
  auto keypair = r1cs_ppzksnark_generator<ppT>(pb.get_constraint_system());

  /**************************************************/
  /* Prover: Fill in both inputs and generate proof */
  /**************************************************/

  /* We just set the value of the input anchors,
   * now execute this function to function the gadget and fill in the other
   * anchors */
  // sha256.generate_r1cs_witness();
  // auto pi = pb.primary_input();
  // auto ai = pb.auxiliary_input();
  // /* If res is not zero, this function will crash complaining that
  //  * the R1CS constraint system is not satisfied. */
  // auto proof = r1cs_ppzksnark_prover<ppT>(keypair.pk,pi,ai,pb.constraint_system);

  // /********************************************/
  // /* Verifier: fill in only the public inputs */
  // /********************************************/
  // for (size_t i = 0; i < dimension; i++)  // Actually, primary_input is a std::vector<FieldT>,
  //   pb.val(A[i]) = public_input[i];       // we can just cast or copy the public_input to get primary input,
  // pi = pb.primary_input();                // but let's pretend that we don't know the implementation details

  // if(r1cs_ppzksnark_verifier_strong_IC<ppT>(keypair.vk,pi,proof)) {
  //   cout << "Verified!" << endl;
  // } else {
  //   cout << "Failed to verify!" << endl;
  // }

  return 0;
}
