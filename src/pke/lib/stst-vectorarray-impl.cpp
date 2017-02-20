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
template class LPCryptoParametersStehleSteinfeld<ILVectorArray2n>;
template class LPPublicKeyEncryptionSchemeStehleSteinfeld<ILVectorArray2n>;
template class LPEncryptionAlgorithmStehleSteinfeld<ILVectorArray2n>;
}
