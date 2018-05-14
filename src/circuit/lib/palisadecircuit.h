/**
 * @file palisadecircuit.h -- High level container for a circuit
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
 * This code provides a container for a circuit
 *
 */

#ifndef SRC_CIRCUIT_LIB_PALISADECIRCUIT_H_
#define SRC_CIRCUIT_LIB_PALISADECIRCUIT_H_

// This will EVENTUALLY be folded into the CryptoContext when it settles

#include <map>
using std::map;
#include "palisade.h"
#include "cryptocontext.h"
#include "circuitnode.h"
#include "circuitgraph.h"

namespace lbcrypto {

typedef	size_t CircuitKey;

template<typename Element>
using CircuitIOPair = pair<CircuitKey,const CircuitValue<Element>&>;

template<typename Element>
using CircuitInput = map<CircuitKey,CircuitValue<Element>>;

template<typename Element>
using CircuitOutput = vector<CircuitIOPair<Element>>;

template<typename Element>
using EF = Plaintext (*)(CryptoContext<Element>, int64_t);

template<typename Element>
class PalisadeCircuit {
	CryptoContext<Element>	cc;
	CircuitGraphWithValues<Element>		g;
	EF<Element> EncodeFunction;

public:
	PalisadeCircuit(CryptoContext<Element> cc, CircuitGraph& cg, EF<Element> EncodeFunction = 0);

	CircuitGraphWithValues<Element>&  GetGraph() { return g; }
	void GenerateOperationList() { g.GenerateOperationList(cc); }
	void ApplyRuntimeEstimates(TimingStatisticsMap& stats) { g.ApplyRuntimeEstimates(stats); }

	CircuitOutput<Element>	CircuitEval(const CircuitInput<Element>& inputs, bool verbose=false );

};

}

#endif /* SRC_CIRCUIT_LIB_PALISADECIRCUIT_H_ */
