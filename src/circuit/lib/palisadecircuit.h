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
typedef map<CircuitKey,shared_ptr<Ciphertext<ILVector2n>>>	CircuitIO;

class PalisadeCircuit {
	CryptoContext<ILVector2n>	cc;

public:
	PalisadeCircuit(CryptoContext<ILVector2n> cc) : cc(cc) {}

	CircuitIO	CircuitEval(CircuitGraph& g, const CircuitIO& inputs) {
		std::cout << "Setting inputs" << std::endl;
		for( auto input : inputs ) {
			CircuitNode *i = g.getNodeById(input.first);
			if( i == 0 ) throw std::logic_error("input " + std::to_string(input.first) + " was not specified");
			i->setValue(input.second);
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
