/*
 * parmfactory.h
 *
 *  Created on: Apr 12, 2017
 *      Author: gerardryan
 */

#ifndef SRC_CORE_LIB_UTILS_PARMFACTORY_H_
#define SRC_CORE_LIB_UTILS_PARMFACTORY_H_

// useful for testing

#include "../lattice/ildcrt2n.h"
#include "math/backend.h"
#include "math/distrgen.h"

#include "utils/inttypes.h"

#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "lattice/ilvector2n.h"

using namespace lbcrypto;

template<typename Params, typename Integer>
inline shared_ptr<Params> GenerateTestParams(usint m, const Integer& modulus, const Integer& rootOfUnity) {
	return shared_ptr<Params>(new Params(m, modulus, rootOfUnity));
}


template<typename Params, typename Integer>
inline shared_ptr<Params> GenerateTestParams(usint m, usint nbits) {
	Integer modulus = FindPrimeModulus<Integer>(m, nbits);
	Integer rootOfUnity = RootOfUnity<Integer>(m, modulus);
	return shared_ptr<Params>(new Params(m, modulus, rootOfUnity));
}

/**
 * Generate an ILDCRTParams with a given number of parms, with cyphertext moduli of at least a given size
 * @param m - order
 * @param numOfTower - # of polynomials
 * @param pbits - number of bits in the prime, to start with
 * @return
 */
inline shared_ptr<ILVectorArray2n::Params> GenerateDCRTParams(usint m, usint ptm, usint numOfTower, usint pbits) {

	if( numOfTower == 0 )
		throw std::logic_error("Can't make parms with numOfTower == 0 ");

	std::vector<native_int::BigBinaryInteger> moduli(numOfTower);

	std::vector<native_int::BigBinaryInteger> rootsOfUnity(numOfTower);

	native_int::BigBinaryInteger ptmI( ptm );

	native_int::BigBinaryInteger q = FindPrimeModulus<native_int::BigBinaryInteger>(m, pbits);
	BigBinaryInteger modulus(1);

	usint j = 0;
	for(;;) {
		moduli[j] = q;
		rootsOfUnity[j] = RootOfUnity(m, q);
		modulus = modulus * BigBinaryInteger(q.ConvertToInt());
		if( ++j == numOfTower )
			break;

		lbcrypto::NextQ(q, ptmI, m, native64::BigBinaryInteger(4), native64::BigBinaryInteger(4));
	}

	shared_ptr<ILDCRTParams> params(new ILVectorArray2n::Params(m, moduli, rootsOfUnity));

	return params;
}


#endif /* SRC_CORE_LIB_UTILS_PARMFACTORY_H_ */
