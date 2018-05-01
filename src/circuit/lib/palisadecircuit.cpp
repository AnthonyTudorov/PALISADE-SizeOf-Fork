/**
 * @file palisadecircuit.cpp -- High level container for a circuit
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

#include "palisadecircuit.h"

namespace lbcrypto {

template<typename Element>
PalisadeCircuit<Element>::PalisadeCircuit(CryptoContext<Element> cc, CircuitGraph& cg, EF<Element> EncodeFunction)
	: cc(cc), g(cg), EncodeFunction(EncodeFunction) {

	// after initializing, search for all ConstPtxt and create a Plaintext for them
	for( auto node : cg.getAllNodes() ) {
		ConstPtxt* n = dynamic_cast<ConstPtxt*>(node.second);
		if( n != 0 ) {
			if( EncodeFunction == 0 )
				throw std::logic_error("Encode function required for plaintexts");
			Plaintext ptxt = (*EncodeFunction)(cc, n->GetInt());
			g.getNodeById(n->GetId())->getValue().SetPlaintext(ptxt);
		}
		ConstInt* i = dynamic_cast<ConstInt*>(node.second);
		if( i != 0 ) {
			if( EncodeFunction == 0 )
				throw std::logic_error("Encode function required for integers");
			Plaintext ptxt = (*EncodeFunction)(cc, i->GetInt());
			g.getNodeById(i->GetId())->getValue().SetPlaintext(ptxt);
		}
	}
}

template<typename Element>
CircuitOutput<Element>
PalisadeCircuit<Element>::CircuitEval(const CircuitInput<Element>& inputs, bool verbose ) {
	g.ClearVisited();

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
			stringstream ss;
			ss << "input number " << input << " type mismatch, expected " << i->GetType() << ", got " << cinput->second.GetType();
			throw std::logic_error(ss.str());
		}

		i->setValue(cinput->second);
	}

	if( verbose ) cout << "Executing" << endl;
	g.Execute(cc);

	if( verbose ) cout << "Gathering outputs" << endl;
	CircuitOutput<Element> retval;
	for( auto output : g.getOutputs() ) {
		retval.push_back( CircuitIOPair<Element>(output, g.getNodeById(output)->getValue()) );
	}
	return retval;
}

}
