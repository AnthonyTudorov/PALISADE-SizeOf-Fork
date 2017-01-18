/**
* @section DESCRIPTION
*
* This code provides basic types for circuit construction in the TALUS framework.
*/

#ifndef TALUS_CIRCUITFUNCTION_H
#define TALUS_CIRCUITFUNCTION_H

#include <string>
#include <vector>
using namespace std;

class CircuitGraph;

class CircuitFunction {
	string	name;		// EvalAdd, EvalMult, etc...
	int		arg_count;	// number of parameters we take

	vector<string>			args;
	CircuitGraph			*contents;

public:
	CircuitFunction(string n, int c) : name(n), arg_count(c), contents(0) {}

	CircuitFunction(string n, vector<string>& args, CircuitGraph* contents)
		: name(n), arg_count(args.size()), args(args), contents(contents) {}

	int getArgcount() { return arg_count; }
	const vector<string>& getArgs() { return args; }
	CircuitGraph *getContents() { return contents; }
};

#endif //TALUS_CIRCUITFUNCTION_H
