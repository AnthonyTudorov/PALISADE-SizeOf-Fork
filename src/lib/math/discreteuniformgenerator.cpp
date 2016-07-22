#include "discreteuniformgenerator.h"
#include "distributiongenerator.h"
#include <sstream>
#include <bitset>
#include "backend.h"

namespace lbcrypto {

DiscreteUniformGenerator::DiscreteUniformGenerator (
	const BigBinaryInteger & modulus)
	: DistributionGenerator () {

	// Set default values for properties.
	m_remainingWidth = 0;
	m_chunksPerValue = 0;

	// We generate the distribution here because its parameters are static.
	// m_distribution = std::uniform_int_distribution<usint>(CHUNK_MIN, CHUNK_MAX);

	SetModulus(modulus);
}

void DiscreteUniformGenerator::SetModulus (const BigBinaryInteger & modulus) {

	m_modulus = modulus;

	// Update values that depend on modulus.
	usint modulusWidth = m_modulus.GetMSB();
	m_chunksPerValue = modulusWidth / CHUNK_WIDTH;
	m_remainingWidth = modulusWidth % CHUNK_WIDTH;
}

BigBinaryInteger DiscreteUniformGenerator::GenerateInteger () const {

	//if (modulus != m_modulus) {
	//	this->SetModulus(modulus);
	//}

	BigBinaryInteger result;
	
	std::uniform_int_distribution<usint> distribution(CHUNK_MIN, CHUNK_MAX);

	do {
		std::stringstream buffer("");
		for (usint i = 0; i < m_chunksPerValue; i++) {
			// Generate the next random value and append it to the buffer.
			usint value = distribution(GetPRNG());
			buffer << std::bitset<CHUNK_WIDTH>(value).to_string();
		}

		// If the chunk width did not fit perfectly, we need to generate a final partial chunk.
		if (m_remainingWidth > 0) {
			usint value = distribution(GetPRNG());
			std::string temp = std::bitset<CHUNK_WIDTH>(value).to_string();
			buffer << temp.substr(CHUNK_WIDTH - m_remainingWidth, CHUNK_WIDTH);
		}

		// Convert the binary into a BBI.
		std::string str = buffer.str();
		result = BigBinaryInteger::BinaryStringToBigBinaryInt(str);
	} while (result > m_modulus);

	return result;
}

BigBinaryVector DiscreteUniformGenerator::GenerateVector(const usint size) const {

	//if (modulus != m_modulus) {
	//	this->SetModulus(modulus);
	//}

	BigBinaryVector v(size,m_modulus);

	for (usint i = 0; i < size; i++) {
	BigBinaryInteger temp(this->GenerateInteger());
		v.SetValAtIndex(i, temp);
	}

	return v;

}

} // namespace lbcrypto
