/*
 * lvector2n-impl.cpp
 *
 *  Created on: Mar 8, 2017
 *      Author: gwryan
 */

#include "ilparams.cpp"
#include "ilvector2n.cpp"
#include "../math/discretegaussiangenerator.cpp"
#include "../math/discreteuniformgenerator.cpp"
#include "../math/binaryuniformgenerator.cpp"
#include "../math/ternaryuniformgenerator.cpp"

// This creates all the necessary class implementations for ILVector2n

namespace lbcrypto {
template class DiscreteGaussianGeneratorImpl<BigBinaryInteger,BigBinaryVector>;
template class BinaryUniformGeneratorImpl<BigBinaryInteger,BigBinaryVector>;
template class TernaryUniformGeneratorImpl<BigBinaryInteger,BigBinaryVector>;
template class DiscreteUniformGeneratorImpl<BigBinaryInteger,BigBinaryVector>;

}

namespace lbcrypto {
template class ILParamsImpl<BigBinaryInteger>;
template class ILVectorImpl<BigBinaryInteger,BigBinaryInteger,BigBinaryVector,ILParams>;

template<>
ILVectorImpl<BigBinaryInteger,BigBinaryInteger,BigBinaryVector,ILParams>::ILVectorImpl(const shared_ptr<ILDCRTParams<BigBinaryInteger>> params, Format format, bool initializeElementToZero) : m_values(nullptr), m_format(format) {
	// construct a local params out of the stuff from the DCRT Params
	m_params.reset( new ILParams(params->GetCyclotomicOrder(), params->GetModulus(), BigBinaryInteger::ONE));

	if (initializeElementToZero) {
		this->SetValuesToZero();
	}
}

}
