/**
 * @file impl.cpp -- instantiates all the circuit classes so that you don't need to #include source
 * @author  TPOC: palisade@njit.edu
 *
 * @section LICENSE
 *
 * Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
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
 * @section DESCRIPTION
 *
 * reads file of needed timings; generates timings for estimator
 *
 */

#include "palisade.h"
#include "encoding/encodings.h"
#include "cryptocontextgen.h"
#include "palisadecircuit.h"
#include "parsedriver.h"

using namespace lbcrypto;

#include "circuitnode.cpp"
#include "circuitgraph.cpp"
#include "palisadecircuit.cpp"
#include "circuitvalue.cpp"

namespace lbcrypto {
bool CircuitOpTrace;

template class InputWithValue<Poly>;
template class ConstIntWithValue<Poly>;
template class ConstPtxtWithValue<Poly>;
template class ModReduceNodeWithValue<Poly>;
template class EvalAddNodeWithValue<Poly>;
template class EvalSubNodeWithValue<Poly>;
template class EvalMultNodeWithValue<Poly>;
template class EvalRShiftNodeWithValue<Poly>;
template class EvalInnerProdNodeWithValue<Poly>;
template class CircuitNodeWithValue<Poly>;
template class CircuitGraphWithValues<Poly>;
template class PalisadeCircuit<Poly>;

template class InputWithValue<NativePoly>;
template class ConstIntWithValue<NativePoly>;
template class ConstPtxtWithValue<NativePoly>;
template class ModReduceNodeWithValue<NativePoly>;
template class EvalAddNodeWithValue<NativePoly>;
template class EvalSubNodeWithValue<NativePoly>;
template class EvalMultNodeWithValue<NativePoly>;
template class EvalRShiftNodeWithValue<NativePoly>;
template class EvalInnerProdNodeWithValue<NativePoly>;
template class CircuitNodeWithValue<NativePoly>;
template class CircuitGraphWithValues<NativePoly>;
template class PalisadeCircuit<NativePoly>;

template class InputWithValue<DCRTPoly>;
template class ConstIntWithValue<DCRTPoly>;
template class ConstPtxtWithValue<DCRTPoly>;
template class ModReduceNodeWithValue<DCRTPoly>;
template class EvalAddNodeWithValue<DCRTPoly>;
template class EvalSubNodeWithValue<DCRTPoly>;
template class EvalMultNodeWithValue<DCRTPoly>;
template class EvalRShiftNodeWithValue<DCRTPoly>;
template class EvalInnerProdNodeWithValue<DCRTPoly>;
template class CircuitNodeWithValue<DCRTPoly>;
template class CircuitGraphWithValues<DCRTPoly>;
template class PalisadeCircuit<DCRTPoly>;
}

