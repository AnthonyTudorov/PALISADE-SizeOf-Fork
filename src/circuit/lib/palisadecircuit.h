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

typedef	size_t CircuitKey;

template<typename Element>
using CircuitIO = map<CircuitKey,CircuitObject<Element>>;

template<typename Element>
class PalisadeCircuit {
	shared_ptr<CryptoContext<Element>>	cc;
	CircuitGraphWithValues<Element>		g;

public:
	PalisadeCircuit(shared_ptr<CryptoContext<Element>> cc, CircuitGraph& cg) : cc(cc), g(cg) {}

	CircuitGraphWithValues<Element>&  GetGraph() { return g; }

	CircuitIO<Element>	CircuitEval(const CircuitIO<Element>& inputs, bool verbose=false ) {
		g.Reset();

		if( verbose ) cout << "Setting inputs" << endl;
		auto circuitInputs = g.getInputs();
		if( verbose ) {
			cout << "inputs: "; for( auto x : g.getInputs() ) cout << x << " "; cout << endl;
			cout << "outputs: "; for( auto x : g.getOutputs() ) cout << x << " "; cout << endl;
		}
		if( circuitInputs.size() != inputs.size() ) {
			throw std::logic_error("Argument count mismatch");
		}

		for( auto input : circuitInputs ) {
			auto cinput = inputs.find(input);
			if( cinput == inputs.end() ) {
				throw std::logic_error("input number " + std::to_string(input) + " is not an input to the circuit");
			}

			CircuitNodeWithValue<Element> *i = g.getNodeById(input);
			if( i == 0 ) throw std::logic_error("input " + std::to_string(input) + " was not specified");

			// type check
			if( i->GetType() != cinput->second.GetType() ) {
				cout << i->GetType() << " " << cinput->second.GetType() << endl;
				throw std::logic_error("input number " + std::to_string(input) + " type mismatch");
			}

			i->setValue(cinput->second);
		}

		if( verbose ) cout << "Executing" << endl;
		g.Execute(cc);

		if( verbose ) cout << "Gathering outputs" << endl;
		CircuitIO<Element> retval;
		for( auto output : g.getOutputs() ) {
			retval[output] = g.getNodeById(output)->getValue();
		}
		return retval;
	}

	void CircuitDump() {

	}
};


#endif /* SRC_CIRCUIT_LIB_PALISADECIRCUIT_H_ */