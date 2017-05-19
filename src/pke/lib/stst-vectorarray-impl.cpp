/*
 * stst-vector-impl.cpp
 *
 *  Created on: Dec 24, 2016
 *      Author: gerardryan
 */

#include "cryptocontext.h"
#include "ltv.h"
#include "stst.h"

namespace lbcrypto {
template class LPCryptoParametersStehleSteinfeld<ILDCRT2n>;
template class LPPublicKeyEncryptionSchemeStehleSteinfeld<ILDCRT2n>;
template class LPEncryptionAlgorithmStehleSteinfeld<ILDCRT2n>;
}
