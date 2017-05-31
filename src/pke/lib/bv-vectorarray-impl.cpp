/*
 * bv-vector-impl.cpp
 *
 *  Created on: Dec 24, 2016
 *      Author: gerardryan
 */

#include "cryptocontext.h"
#include "bv.cpp"

namespace lbcrypto {
template class LPCryptoParametersBV<ILDCRT2n>;
template class LPPublicKeyEncryptionSchemeBV<ILDCRT2n>;
template class LPAlgorithmBV<ILDCRT2n>;
}
