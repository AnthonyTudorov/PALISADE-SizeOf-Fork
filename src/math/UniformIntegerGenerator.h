//
// Created by matt on 12/10/15.
//

#ifndef LBCRYPTO_STUDENT_EDITION_UNIFORMINTEGERGENERATOR_H_
#define LBCRYPTO_STUDENT_EDITION_UNIFORMINTEGERGENERATOR_H_

#include "backend.h"
//#include "DistributionGenerator.h"

namespace lbcrypto {
    //class UniformIntegerGenerator: DistributionGenerator
    //{
    //public:
    //	UniformIntegerGenerator(); //srand(time(NULL)) is called here
    //	UniformIntegerGenerator(const BigBinaryInteger& lower, const BigBinaryInteger& upper);
    //	~UniformIntegerGenerator();
    //
    //	//ACCESSORS
    //
    //    BigBinaryInteger& GetLowerBound() const;
    //	BigBinaryInteger& GetUpperBound() const;
    //    void SetLowerBound(const BigBinaryInteger& lower);
    //	void SetUpperBound(const BigBinaryInteger& upper);
    //
    //    BigBinaryInteger& GenerateInteger() const;
    //    BigBinaryVector& GenerateVector(int size) const;
    //
    //private:
    //    //it is assumed that lower and higher bounds for uniform random distribution can be up to the value of ciphertext modulus
    //	BigBinaryInteger m_lowerBound;
    //    BigBinaryInteger m_upperBound;
    //	//I don't believe we need to store the seed used for the previous case; it can be set to srand (time(NULL));
    //	//if it is faster to keep working incrementally with the same seed, we can add it
    //	//though in this case, it is not clear how parallelization can be achieved
    //};
}

#endif // LBCRYPTO_STUDENT_EDITION_UNIFORMINTEGERGENERATOR_H_
