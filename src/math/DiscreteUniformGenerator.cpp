//
// Created by matt on 12/10/15.
//

#include "DiscreteUniformGenerator.h"

#include "backend.h"

namespace lbcrypto {

    DiscreteUniformGenerator::DiscreteUniformGenerator(){
    }

    DiscreteUniformGenerator::~DiscreteUniformGenerator(){
        //Destructor of DiscreteUniformGenerator is called
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
    BigBinaryInteger DiscreteUniformGenerator::GenerateInteger(const BigBinaryInteger &modulus) const{
        //if m_modulus ~= modulus {
        //	this->InitializeVals(modulus);
        //}
        usint moduloLength = modulus.GetMSB();
        usint noOfIter = ((moduloLength % LENOFMAX) == 0) ? (moduloLength/LENOFMAX) : (moduloLength/LENOFMAX) + 1;
        usint remainder = moduloLength % LENOFMAX;
        usint randNum;
        std::string temp;
        std::string bigBinaryInteger = "";
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(DiscreteUniformGenerator::MINVAL, DiscreteUniformGenerator::MAXVAL);
        for(usint i=0; i< noOfIter; ++i) {
            randNum = dis(gen);
            if(remainder != 0 && i == noOfIter-1) {
                temp = std::bitset<DiscreteUniformGenerator::LENOFMAX>(randNum).to_string();
                bigBinaryInteger += temp.substr(LENOFMAX-remainder, LENOFMAX);
            } else {
                bigBinaryInteger += std::bitset<DiscreteUniformGenerator::LENOFMAX>(randNum).to_string();
            }
        }
        BigBinaryInteger randBigBinaryInteger(BigBinaryInteger::BinaryToBigBinaryInt(bigBinaryInteger));
        if(randBigBinaryInteger < modulus)
            return randBigBinaryInteger;
        else
            return DiscreteUniformGenerator::GenerateInteger(modulus);
    }

    BigBinaryVector DiscreteUniformGenerator::GenerateVector(usint size, const BigBinaryInteger &modulus) const{
        BigBinaryVector randBigBinaryVector(size);
        for(usint index = 0; index<size; ++index) {
            BigBinaryInteger temp(this->GenerateInteger(modulus));
            randBigBinaryVector.SetValAtIndex(index, temp);
        }
        return randBigBinaryVector;
    }

}