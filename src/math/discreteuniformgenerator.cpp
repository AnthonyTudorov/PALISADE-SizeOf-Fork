#include "discreteuniformgenerator.h"
#include "distributiongenerator.h"
#include "discretedistributiongenerator.h"
#include <sstream>
#include "backend.h"

namespace lbcrypto {

DiscreteUniformGenerator::DiscreteUniformGenerator (
  const BigBinaryInteger & modulus)
  : DiscreteDistributionGenerator (modulus) {

  // Set default values for properties.
  this->remainder_width_  = 0;
  this->chunks_per_value_ = 0;

  // We generate the distribution here because its parameters are static.
  this->distribution_ = std::uniform_int_distribution<usint>(CHUNK_MIN, CHUNK_MAX);

  this->SetModulus(modulus);
}

void DiscreteUniformGenerator::SetModulus (const BigBinaryInteger & modulus) {

  // Call parent version of set modulus.
  DiscreteDistributionGenerator::SetModulus(modulus);

  // Update values that depend on modulus.
  usint modulo_width      = this->modulus_.GetMSB();
  this->chunks_per_value_ = modulo_width / CHUNK_WIDTH;
  this->remainder_width_  = modulo_width % CHUNK_WIDTH;
}

BigBinaryInteger DiscreteUniformGenerator::GenerateInteger () {

  BigBinaryInteger result;

  do {
    std::stringstream buffer("");
    for (usint i = 0; i < this->chunks_per_value_; i++) {
      // Generate the next random value and append it to the buffer.
      usint value = this->distribution_(this->GetPRNG());
      buffer << std::bitset<CHUNK_WIDTH>(value).to_string();
    }

    // If the chunk width did not fit perfectly, we need to generate a final partial chunk.
    if (this->remainder_width_ > 0) {
      usint value = this->distribution_(this->GetPRNG());
      std::string temp = std::bitset<CHUNK_WIDTH>(value).to_string();
      buffer << temp.substr(CHUNK_WIDTH - this->remainder_width_, CHUNK_WIDTH);
    }

    // Convert the binary into a BBI.
    std::string str = buffer.str();
    result = BigBinaryInteger::BinaryToBigBinaryInt(str);
  } while (result > this->modulus_);

  return result;

}

BigBinaryVector DiscreteUniformGenerator::GenerateVector(const usint size) {

  BigBinaryVector randBigBinaryVector(size);

  for (usint i = 0; i < size; i++) {
    BigBinaryInteger temp(this->GenerateInteger());
    randBigBinaryVector.SetValAtIndex(i, temp);
  }

  return randBigBinaryVector;

}

} // namespace lbcrypto
