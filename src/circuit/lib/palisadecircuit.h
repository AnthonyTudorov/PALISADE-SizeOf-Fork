/*
 * palisadecircuit.h
 *
 *  Created on: May 16, 2017
 *      Author: gerardryan
 */

#ifndef SRC_CIRCUIT_LIB_PALISADECIRCUIT_H_
#define SRC_CIRCUIT_LIB_PALISADECIRCUIT_H_

// This will EVENTUALLY be folded into the CryptoContext when it settles

#include <map>
using std::map;
#include "palisade.h"
#include "cryptocontext.h"
#include "circuitnode.h"

typedef	size_t CircuitKey;
typedef map<CircuitKey,CircuitObject>	CircuitIO;

class PalisadeCircuit {
	CryptoContext<ILDCRT2n>	cc;

public:
	PalisadeCircuit(CryptoContext<ILDCRT2n> cc) : cc(cc) {}

	void CircuitSetup(CircuitGraph& g, bool verbose) {
		if( verbose ) cout << "Setting up" << endl;
		g.Prepare();
	}

	CircuitIO	CircuitEval(CircuitGraph& g, const CircuitIO& inputs, bool verbose ) {
		if( verbose ) cout << "Setting inputs" << endl;
		auto circuitInputs = g.getInputs();
		if( verbose ) {
			cout << "inputs: "; for( auto x : g.getInputs() ) cout << x << " "; cout << endl;
			cout << "outputs: "; for( auto x : g.getOutputs() ) cout << x << " "; cout << endl;
			cout << circuitInputs.size() << endl << inputs.size() << endl;
		}
		if( circuitInputs.size() != inputs.size() ) {
			throw std::logic_error("Argument count mismatch");
		}

		for( auto input : circuitInputs ) {
			auto cinput = inputs.find(input);
			if( cinput == inputs.end() ) {
				throw std::logic_error("input number " + std::to_string(input) + " is not an input to the circuit");
			}

			CircuitNode *i = g.getNodeById(input);
			if( i == 0 ) throw std::logic_error("input " + std::to_string(input) + " was not specified");

			// type check
			if( i->GetType() != cinput->second.GetType() ) {
				cout << i->GetType() << " " << cinput->second.GetType() << endl;
				throw std::logic_error("input number " + std::to_string(input) + " type mismatch");
			}

			cout << i->GetId() << " before: " << i->GetType();
			i->setValue(cinput->second);
			cout << " after " << i->GetType() << endl;
		}

		if( verbose ) cout << "Executing" << endl;
		g.Execute(cc);

		if( verbose ) cout << "Gathering outputs" << endl;
		CircuitIO retval;
		for( auto output : g.getOutputs() ) {
			retval[output] = g.getNodeById(output)->getValue();
		}
		return retval;
	}

	void CircuitDump(CircuitGraph& g) {

	}
};


#endif /* SRC_CIRCUIT_LIB_PALISADECIRCUIT_H_ */
