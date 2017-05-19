/*
 * ltv-vector-impl.cpp
 *
 *  Created on: Dec 24, 2016
 *      Author: gerardryan
 */

#include "cryptocontext.h"
#include "ltv.cpp"

namespace lbcrypto {
template class LPCryptoParametersLTV<ILDCRT2n>;
template class LPPublicKeyEncryptionSchemeLTV<ILDCRT2n>;
template class LPAlgorithmLTV<ILDCRT2n>;
template class LPAlgorithmPRELTV<ILDCRT2n>;
template class LPAlgorithmSHELTV<ILDCRT2n>;
template class LPLeveledSHEAlgorithmLTV<ILDCRT2n>;
}
