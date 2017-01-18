/*
 * CircuitSim.h
 *
 *  Created on: Aug 15, 2016
 *      Author: gerardryan
 */

#ifndef SRC_FHE_CIRCUITSIM_H_
#define SRC_FHE_CIRCUITSIM_H_

#include "CircuitFunction.h"
class CircuitNode;

#include <map>
#include <vector>
#include <string>
#include <algorithm>
#include <iostream>
using namespace std;

class CircuitSim {
	map<string, uint32_t> params;

	// names of inputs and outputs;
	vector<string> inputs;
	vector<string> outputs;

	vector<string> argCollection;

	map<string, CircuitFunction*> knownFunctions;

public:
	CircuitSim();
	virtual ~CircuitSim() {}

	uint32_t getRingDimension() { return params["ringdim"]; }
	uint32_t getPlaintextModulus() { return params["ptmod"]; }
	void setParam(string param, uint32_t value) { params[param] = value; }

	void clearArgs() { argCollection.clear(); }
	vector<string>& getArgs() { return argCollection; }
	bool addArg(string s) {
		if( std::find(argCollection.begin(), argCollection.end(), s) == argCollection.end() ) {
			argCollection.push_back(s);
			return true;
		}
		return false;
	}

	bool addInput(string s) {
		if( std::find(inputs.begin(), inputs.end(), s) == inputs.end() ) {
			inputs.push_back(s);
			return true;
		}
		return false; // duplicate identifier
	}

	bool isInput(string s) { return std::find(inputs.begin(), inputs.end(), s) != inputs.end(); }

	const vector<string>& getInputs() const { return inputs; }

	bool addOutput(string s) {
		if( std::find(outputs.begin(), outputs.end(), s) == outputs.end() ) {
			outputs.push_back(s);
			return true;
		}
		return false; // duplicate identifier
	}

	bool isOutput(string s) { return std::find(outputs.begin(), outputs.end(), s) != outputs.end(); }

	const vector<string>& getOutputs() const { return outputs; }

	bool addFunction(string function, int argcount);

	bool addUserFunction(string function, vector<string>& args, CircuitGraph* body);

	int getFunctionArgCount(string f) {
		map<string, CircuitFunction*>::iterator fit = knownFunctions.find(f);

		if( fit == knownFunctions.end() ) return -1;

		return fit->second->getArgcount();
	}

	CircuitGraph *UserFunctionFactory(string func, vector<CircuitNode *>& inputs);
};

#endif /* SRC_FHE_CIRCUITSIM_H_ */
