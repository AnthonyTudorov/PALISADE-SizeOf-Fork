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
	m_remainingWidth = 0;
	m_chunksPerValue = 0;

	// We generate the distribution here because its parameters are static.
	m_distribution = std::uniform_int_distribution<usint>(CHUNK_MIN, CHUNK_MAX);

	SetModulus(modulus);
}

void DiscreteUniformGenerator::SetModulus (const BigBinaryInteger & modulus) {

	// Call parent version of set modulus.
	DiscreteDistributionGenerator::SetModulus(modulus);

	// Update values that depend on modulus.
	usint modulusWidth = m_modulus.GetMSB();
	m_chunksPerValue = modulusWidth / CHUNK_WIDTH;
	m_remainingWidth = modulusWidth % CHUNK_WIDTH;
}

BigBinaryInteger DiscreteUniformGenerator::GenerateInteger () {
	BigBinaryInteger result;

	do {
		std::stringstream buffer("");
		for (usint i = 0; i < m_chunksPerValue; i++) {
			// Generate the next random value and append it to the buffer.
			usint value = m_distribution(GetPRNG());
			buffer << std::bitset<CHUNK_WIDTH>(value).to_string();
		}

		// If the chunk width did not fit perfectly, we need to generate a final partial chunk.
		if (m_remainingWidth > 0) {
			usint value = m_distribution(GetPRNG());
			std::string temp = std::bitset<CHUNK_WIDTH>(value).to_string();
			buffer << temp.substr(CHUNK_WIDTH - m_remainingWidth, CHUNK_WIDTH);
		}

		// Convert the binary into a BBI.
		std::string str = buffer.str();
		result = BigBinaryInteger::BinaryToBigBinaryInt(str);
	} while (result > m_modulus);

	return result;
}

BigBinaryVector DiscreteUniformGenerator::GenerateVector(const usint size) {

	BigBinaryVector v(size);
	v.SetModulus(m_modulus);

	for (usint i = 0; i < size; i++) {
	BigBinaryInteger temp(this->GenerateInteger());
		v.SetValAtIndex(i, temp);
	}

	return v;

}

} // namespace lbcrypto
