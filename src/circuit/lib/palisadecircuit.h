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
	CryptoContext<ILVector2n>	cc;

public:
	PalisadeCircuit(CryptoContext<ILVector2n> cc) : cc(cc) {}

	CircuitIO	CircuitEval(CircuitGraph& g, const CircuitIO& inputs) {
		std::cout << "Setting inputs" << std::endl;
		auto circuitInputs = g.getInputs();
		cout << "inputs: "; for( auto x : g.getInputs() ) cout << x << " "; cout << endl;
		cout << "outputs: "; for( auto x : g.getOutputs() ) cout << x << " "; cout << endl;
		cout << circuitInputs.size() << endl << inputs.size() << endl;
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

			i->setValue(cinput->second);
		}

		std::cout << "Executing" << std::endl;
		g.Execute(cc);

		std::cout << "Gathering outputs" << std::endl;
		CircuitIO retval;
		for( auto output : g.getOutputs() ) {
			retval[output] = g.getNodeById(output)->getValue();
		}
		return retval;
	}
};


#endif /* SRC_CIRCUIT_LIB_PALISADECIRCUIT_H_ */
