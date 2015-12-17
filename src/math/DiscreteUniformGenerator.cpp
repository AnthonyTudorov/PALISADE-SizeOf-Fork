//
// Created by matt on 12/10/15.
//

#include "DiscreteUniformGenerator.h"
#include <sstream>
#include "DistributionGenerator.h"
#include "DiscreteDistributionGenerator.h"

#include "backend.h"

namespace lbcrypto {

    DiscreteUniformGenerator::DiscreteUniformGenerator (const BigBinaryInteger & modulus) : DiscreteDistributionGenerator (modulus) {
        // We generate the distribution here because the parameters are static.
        this->distribution = std::uniform_int_distribution<usint>(CHUNK_MIN, CHUNK_MAX);
    }

    void DiscreteUniformGenerator::setModulus (const BigBinaryInteger & modulus) {
        // Why do work when you don't need to?
        if (this->modulus == modulus) {
            return;
        }

        //  Update local modulus.
        this->modulus = modulus;

        // Update values that depend on modulus.
        usint moduloWidth = this->modulus.GetMSB();
        this->chunksPerValue = moduloWidth / CHUNK_WIDTH;
        this->remainingWidth = moduloWidth % CHUNK_WIDTH;
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
    BigBinaryInteger DiscreteUniformGenerator::generateInteger () {

        auto prng = this->getPRNG();
        std::stringstream buffer("");

        for (usint i = 0; i < this->chunksPerValue; i++) {
            // generate the next random value, then append it's binary form to the buffer
            usint value = this->distribution(prng);
            buffer << std::bitset<CHUNK_WIDTH>(value).to_string();
        }

        // If the chunk width did not fit perfectly, we need to generate a final partial chunk
        if (this->remainingWidth > 0) {
            usint value = this->distribution(prng);
            std::string temp = std::bitset<CHUNK_WIDTH>(value).to_string();
            buffer << temp.substr(CHUNK_WIDTH - this->remainingWidth, CHUNK_WIDTH);
        }

        // convert the binary into a BBI
        BigBinaryInteger result(BigBinaryInteger::BinaryToBigBinaryInt(buffer.str()));

        if (result < this->modulus) {
            return result;
        } else {
            return this->generateInteger();
        }
    }

// original version
//    BigBinaryInteger DiscreteUniformGenerator::generateInteger () {
//        //if m_modulus != modulus {
//        //	this->InitializeVals(modulus);
//        //}
//        usint moduloLength = this->modulus.GetMSB();
//        usint noOfIter     = ((moduloLength % CHUNK_WIDTH) == 0) ? (moduloLength/CHUNK_WIDTH) : (moduloLength/CHUNK_WIDTH) + 1;
//        usint remainder    = moduloLength % CHUNK_WIDTH;
//        usint randNum;
//        std::string temp;
//        std::string bigBinaryInteger = "";
//        std::uniform_int_distribution<usint> dis(CHUNK_MIN, CHUNK_MAX);
//
//        for (usint i = 0; i < noOfIter; ++i) {
//            randNum = dis(this->getPRNG());
//            if (remainder != 0 && i == noOfIter - 1) {
//                temp = std::bitset<CHUNK_WIDTH>(randNum).to_string();
//                bigBinaryInteger += temp.substr(CHUNK_WIDTH - remainder, CHUNK_WIDTH);
//            } else {
//                bigBinaryInteger += std::bitset<CHUNK_WIDTH>(randNum).to_string();
//            }
//        }
//
//        BigBinaryInteger randBigBinaryInteger(BigBinaryInteger::BinaryToBigBinaryInt(bigBinaryInteger));
//
//        // if the random number is within modulus, return
//        // otherwise, generate another random number
//        if (randBigBinaryInteger < modulus)
//            return randBigBinaryInteger;
//        else
//            return this->generateInteger();
//    }

    BigBinaryVector DiscreteUniformGenerator::generateVector(const usint size) {
        BigBinaryVector randBigBinaryVector(size);
        for(usint i = 0; i < size; i++) {
            BigBinaryInteger temp(this->generateInteger());
            randBigBinaryVector.SetValAtIndex(i, temp);
        }
        return randBigBinaryVector;
    }

}