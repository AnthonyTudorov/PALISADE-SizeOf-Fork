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
#include "utils/parmfactory.h"

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


#endif /* TEST_SRC_CRYPTOLAYERTESTS_H_ */
