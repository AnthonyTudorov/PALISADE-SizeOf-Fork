/*
 * ciphertext-vector-impl.cpp
 *
 *  Created on: Dec 24, 2016
 *      Author: gerardryan
 */

#include "cryptocontext.h"
#include "lattice/ilvector2n.cpp"
#include "lattice/ilvectorarray2n.cpp"
#include "ciphertext.cpp"

namespace lbcrypto {
extern template class CryptoContext<ILDCRT2n>;

template class Ciphertext<ILDCRT2n>;
}

