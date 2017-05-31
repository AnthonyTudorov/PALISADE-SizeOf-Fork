/*
 * fv-vector-impl.cpp
 *
 *  Created on: Dec 24, 2016
 *      Author: gerardryan
 */

#include "cryptocontext.h"
#include "fv.cpp"

namespace lbcrypto {
template class LPCryptoParametersFV<ILDCRT2n>;
template class LPPublicKeyEncryptionSchemeFV<ILDCRT2n>;
template class LPAlgorithmFV<ILDCRT2n>;
template class LPAlgorithmParamsGenFV<ILDCRT2n>;
}
