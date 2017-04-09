/*
 * CircuitSim.cpp
 *
 *  Created on: Aug 15, 2016
 *      Author: gerardryan
 */

#include "CircuitSim.h"
#include "CircuitGraph.h"

CircuitSim::CircuitSim() {
	// must create built in functions and add them to the function table
	addFunction("EvalAdd", 2);
	addFunction("EvalMult", 2);
	addFunction("EvalNeg", 1);
}

CircuitGraph *
CircuitSim::UserFunctionFactory(string func, vector<CircuitNode *>& inputs)
{
//	map<string, CircuitFunction*>::iterator it = knownFunctions.find(func);
//
//	if( it == knownFunctions.end() ) return 0;
//
//	CircuitFunction *userFunc = it->second;
//
//	if( inputs.size() != userFunc->getArgs().size() ) {
//		cerr << "Arg count mismatch on use of function " << func << endl;
//		return 0;
//	}
//
//	// clone the graph
//	CircuitGraph *clone = new CircuitGraph(*userFunc->getContents());
//
//	// the inputs passed to the function have to be connected into the function
//	// so we need to remap the inputs
//
//	map<string,string> nameMap;
//	map<CircuitNode *, CircuitNode *> valueMap;
//	set<CircuitNode*> replaced;
//	for( int i = 0; i < clone->getInputs().size(); i++ ) {
//		string oldInputNodeName = clone->getInput(i);
//		CircuitNode *oldInputNode = clone->getNodeByName( oldInputNodeName );
//
//		nameMap[oldInputNodeName] = inputs[i]->getName();
//		valueMap[oldInputNode] = inputs[i];
//		replaced.insert(oldInputNode);
//	}
//
//	// replace all instances of a name in nameMap with the new value
//	// replace all instances of a pointer in valueMap with the new value
//	clone->bindParameters(nameMap, valueMap);
//
//	for( CircuitNode* n : replaced ) {
//		clone->removeNode(n);
//		delete n;
//	}
//
//	return clone;
	return 0;
}

bool
CircuitSim::addFunction(string function, int argcount)
{
	if( knownFunctions.find(function) != knownFunctions.end() )
		return false; // duplicate

	knownFunctions[function] = new CircuitFunction(function, argcount);
	return true;
}

bool
CircuitSim::addUserFunction(string function, vector<string>& args, CircuitGraph* body)
{
	if( knownFunctions.find(function) != knownFunctions.end() )
		return false; // duplicate

	knownFunctions[function] = new CircuitFunction(function, args, body);
	return true;
}
