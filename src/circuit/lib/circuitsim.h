/*
 * CircuitSim.h
 *
 *  Created on: Aug 15, 2016
 *      Author: gerardryan
 */

#ifndef SRC_FHE_CIRCUITSIM_H_
#define SRC_FHE_CIRCUITSIM_H_

#include "circuitfunction.h"
class CircuitNode;

#include <map>
#include <vector>
#include <string>
#include <algorithm>
#include <iostream>
using namespace std;

// OLD DEPRECATED CODE

class CircuitSim {
	map<string, uint32_t> params;

	// names of inputs and outputs;
	vector<int> inputs;
	vector<int> outputs;

	vector<int> argCollection;

	map<string, CircuitFunction*> knownFunctions;

public:
	CircuitSim();
	virtual ~CircuitSim() {}

	void setParam(string param, uint32_t value) { params[param] = value; }

	void clearArgs() { argCollection.clear(); }
	vector<int>& getArgs() { return argCollection; }
	bool addArg(int s) {
		if( std::find(argCollection.begin(), argCollection.end(), s) == argCollection.end() ) {
			argCollection.push_back(s);
			return true;
		}
		return false;
	}

	bool addInput(int s) {
		if( std::find(inputs.begin(), inputs.end(), s) == inputs.end() ) {
			inputs.push_back(s);
			return true;
		}
		return false; // duplicate identifier
	}

	bool isInput(int s) { return std::find(inputs.begin(), inputs.end(), s) != inputs.end(); }

	const vector<int>& getInputs() const { return inputs; }

	bool addOutput(int s) {
		if( std::find(outputs.begin(), outputs.end(), s) == outputs.end() ) {
			outputs.push_back(s);
			return true;
		}
		return false; // duplicate identifier
	}

	bool isOutput(int s) { return std::find(outputs.begin(), outputs.end(), s) != outputs.end(); }

	const vector<int>& getOutputs() const { return outputs; }

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
