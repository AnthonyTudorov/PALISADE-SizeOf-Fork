/**
 * @file be6-poly-impl.cpp This file contains template instantiations for all classes using math be6
 *
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "../math/backend.h"
#include "../lattice/backend.h"
#include "../math/matrix.cpp"

#include "elemparams.cpp"
#include "ilparams.cpp"
#include "poly.cpp"

namespace lbcrypto {

template class ElemParams<M6Integer>;
template class ILParamsImpl<M6Integer>;
template class PolyImpl<M6Vector>;

template class Matrix<M6Poly>;
ONES_FOR_TYPE(M6Poly)
IDENTITY_FOR_TYPE(M6Poly)
GADGET_FOR_TYPE(M6Poly)
NORM_FOR_TYPE(M6Poly)
MATRIX_NOT_SERIALIZABLE(M6Poly)
SPLIT64_FOR_TYPE(M6Poly)
SPLIT64ALT_FOR_TYPE(M6Poly)
SPLIT32ALT_FOR_TYPE(M6Poly)

}
