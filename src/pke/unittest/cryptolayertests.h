/*
 * cryptolayertests.h
 *
 *  Created on: Dec 22, 2016
 *      Author: gerardryan
 */

#ifndef TEST_SRC_CRYPTOLAYERTESTS_H_
#define TEST_SRC_CRYPTOLAYERTESTS_H_

#include "palisade.h"

#include "encoding/byteplaintextencoding.h"
#include "encoding/intplaintextencoding.h"

using namespace lbcrypto;

// this header contains some inline helper functions used to unit test PALISADE

/**
 * Generate Test Plaintext
 * @param cyclotomicOrder for the output vectors - used to calculate chunk size
 * @param ptm - plaintext modulus - used to calculate chunk size
 * @param plaintextShort
 * @param plaintextFull
 * @param plaintextLong
 */
inline void GenerateTestPlaintext(int cyclotomicOrder, const BigBinaryInteger& ptm,
	BytePlaintextEncoding& plaintextShort,
	BytePlaintextEncoding& plaintextFull,
	BytePlaintextEncoding& plaintextLong) {
	size_t strSize = plaintextShort.GetChunksize(cyclotomicOrder, ptm);

	auto randchar = []() -> char {
        const char charset[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";
        const size_t max_index = (sizeof(charset) - 1);
        return charset[ rand() % max_index ];
	};

	string shortStr(strSize/2,0);
	std::generate_n(shortStr.begin(), strSize/2, randchar);
	plaintextShort = shortStr;

	string fullStr(strSize,0);
	std::generate_n(fullStr.begin(), strSize, randchar);
	plaintextFull = fullStr;

	string longStr(strSize*2,0);
	std::generate_n(longStr.begin(), strSize*2, randchar);
	plaintextLong = longStr;
}

/**
 * Generate an ILDCRTParams with a given number of parms, with cyphertext moduli of at least a given size
 * @param m - order
 * @param numOfTower - # of polynomials
 * @param pbits - number of bits in the prime, to start with
 * @return
 */
inline shared_ptr<ILDCRTParams> GenerateTestDCRTParams(usint m, usint numOfTower, usint pbits) {
	std::vector<native64::BigBinaryInteger> moduli(numOfTower);

	std::vector<native64::BigBinaryInteger> rootsOfUnity(numOfTower);

	native64::BigBinaryInteger q(1<<pbits - 1);
	native64::BigBinaryInteger temp;
	BigBinaryInteger modulus(BigBinaryInteger::ONE);

	for (int j = 0; j < numOfTower; j++) {
		lbcrypto::NextQ(q, native64::BigBinaryInteger::FIVE, m, native64::BigBinaryInteger::FOUR, native64::BigBinaryInteger::FOUR);
		moduli[j] = q;
		rootsOfUnity[j] = RootOfUnity(m, moduli[j]);
		modulus = modulus * BigBinaryInteger(moduli[j].ConvertToInt());
	}

	shared_ptr<ILDCRTParams> params(new ILDCRTParams(m, moduli, rootsOfUnity));

	return params;
}



#endif /* TEST_SRC_CRYPTOLAYERTESTS_H_ */
