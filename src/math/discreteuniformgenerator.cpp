//
// Created by matt on 12/10/15.
//

#include "discreteuniformgenerator.h"
#include "distributiongenerator.h"
#include "discretedistributiongenerator.h"
#include <sstream>
#include "backend.h"

namespace lbcrypto {

DiscreteUniformGenerator::DiscreteUniformGenerator (const BigBinaryInteger & modulus) : DiscreteDistributionGenerator (modulus) {
    // We generate the distribution here because the parameters are static.
    this->distribution_ = std::uniform_int_distribution<usint>(CHUNK_MIN, CHUNK_MAX);
    this->SetModulus(modulus);
}

void DiscreteUniformGenerator::SetModulus (const BigBinaryInteger & modulus) {

    DiscreteDistributionGenerator::SetModulus(modulus);

    // Update values that depend on modulus.
    usint modulo_width      = this->modulus_.GetMSB();
    this->chunks_per_value_ = modulo_width / CHUNK_WIDTH;
    this->remainder_width_ = modulo_width % CHUNK_WIDTH;
}

/*
void DiscreteUniformGenerator::InitializeVals(const BigBinaryInteger &modulus){
//m_modulus = modulus;
moduloLength = modulus.GetMSB();
noOfIter = ((moduloLength % LENOFMAX) == 0) ? (moduloLength/LENOFMAX) : (moduloLength/LENOFMAX) + 1;
remainder = moduloLength % LENOFMAX;
// std::cout << "moduloLength = " << moduloLength << std::endl;
// std::cout << "noOfIter = " << noOfIter << std::endl;
// std::cout << "remainder = " << remainder << std::endl;
// std::cout << "MAXVAL = " << MAXVAL << std::endl;
}
*/

// updated version using string streams and comments!
BigBinaryInteger DiscreteUniformGenerator::GenerateInteger () {
    BigBinaryInteger result;

    do {
        std::stringstream buffer("");
        for (usint i = 0; i < this->chunks_per_value_; i++) {
            // generate the next random value, then append it's binary form to the buffer
            usint value = this->distribution_(this->GetPRNG());
            buffer << std::bitset<CHUNK_WIDTH>(value).to_string();
        }

        // If the chunk width did not fit perfectly, we need to generate a final partial chunk
        if (this->remainder_width_ > 0) {
            usint value = this->distribution_(this->GetPRNG());
            std::string temp = std::bitset<CHUNK_WIDTH>(value).to_string();
            buffer << temp.substr(CHUNK_WIDTH - this->remainder_width_, CHUNK_WIDTH);
        }

        // convert the binary into a BBI
        std::string str = buffer.str();
        result = BigBinaryInteger::BinaryToBigBinaryInt(str);
    } while (result > this->modulus_);

    return result;
}

// original version
    BigBinaryInteger DiscreteUniformGenerator::GenerateInteger_old () {
        //if m_modulus != modulus {
        //	this->InitializeVals(modulus);
        //}
        usint moduloLength = this->modulus_.GetMSB();
        usint noOfIter     = ((moduloLength % CHUNK_WIDTH) == 0) ? (moduloLength/CHUNK_WIDTH) : (moduloLength/CHUNK_WIDTH) + 1;
        usint remainder    = moduloLength % CHUNK_WIDTH;
        usint randNum;
        std::string temp;
        std::string bigBinaryInteger = "";
        std::uniform_int_distribution<usint> dis(CHUNK_MIN, CHUNK_MAX);

        for (usint i = 0; i < noOfIter; ++i) {
            randNum = dis(this->GetPRNG());
            if (remainder != 0 && i == noOfIter - 1) {
                temp = std::bitset<CHUNK_WIDTH>(randNum).to_string();
                bigBinaryInteger += temp.substr(CHUNK_WIDTH - remainder, CHUNK_WIDTH);
            } else {
                bigBinaryInteger += std::bitset<CHUNK_WIDTH>(randNum).to_string();
            }
        }
        BigBinaryInteger randBigBinaryInteger(BigBinaryInteger::BinaryToBigBinaryInt(bigBinaryInteger));

        // if the random number is within modulus, return
        // otherwise, generate another random number
        if (randBigBinaryInteger < this->modulus_)
            return randBigBinaryInteger;
        else
            return this->GenerateInteger_old();
    }

BigBinaryVector DiscreteUniformGenerator::GenerateVector(const usint size) {
    BigBinaryVector randBigBinaryVector(size);
    for(usint i = 0; i < size; i++) {
        BigBinaryInteger temp(this->GenerateInteger());
        randBigBinaryVector.SetValAtIndex(i, temp);
    }
    return randBigBinaryVector;
}

} // namespace lbcrypto