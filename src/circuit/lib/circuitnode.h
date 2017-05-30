#ifndef CIRCUITNODE_H
#define CIRCUITNODE_H

#include <string>
#include <vector>
#include <map>
#include <queue>
#include <set>
#include <iostream>
#include <typeinfo>

using std::string;
using std::vector;
using std::map;
using std::queue;
using std::set;
using std::ostream;

#include "value.h"
#include "circuitgraph.h"
#include "palisade.h"
#include "cryptocontext.h"

// This class is meant to represent a node in a circuit
// the node can have several inputs, and it has one output
// nodes are identified by a node id
class CircuitNode {

public:
	CircuitNode(int nodeID) {
		this->nodeId = nodeID;
		this->nodeInputDepth = this->nodeOutputDepth = 0;
		is_output = false;
	}
	virtual ~CircuitNode() {}

	int GetId() const { return nodeId; }

	const vector<int>& getInputs() const { return inputs; }
	int getInput(int i) { return inputs[i]; }
	void setInput(int inputIdx, int nodeId) { inputs[inputIdx] = nodeId; }

	const set<int>& getOutputs() const { return outputs; }
	void addOutput(int n) { outputs.insert(n); }
	void delOutput(int n) { outputs.erase(n); }

	void setAsOutput() { is_output = true; }
	void unsetAsOutput() { is_output = false; }

	const int getInputDepth() const { return nodeInputDepth; }
	const int getOutputDepth() const { return nodeOutputDepth; }
	void resetDepth() { this->nodeInputDepth = this->nodeOutputDepth = 0; }
	void setInputDepth(int newDepth) { nodeInputDepth = newDepth; }
	void setOutputDepth(int newDepth) { nodeOutputDepth = newDepth; }
	void resetOutputDepth(int newDepth) { nodeOutputDepth = newDepth; }

	Value& getValue() { return value; }
	const Value& getValue() const { return value; }
	void setValue(const Value& v) { value = v; }

	virtual void setBottomUpDepth() { nodeInputDepth = nodeOutputDepth; } // by default, nodeOutputDepth does not change
	virtual string getNodeLabel() const = 0;
	virtual bool isModReduce() const { return false; }

	virtual uint32_t getRuntime() { return 0; }

	virtual Value eval(CryptoContext<ILVector2n>& cc, CircuitGraph& cg) { return value; }

	friend ostream& operator<<(ostream& out, const CircuitNode& n);

protected:
	bool			is_output;
	int				nodeId;

	vector<int>		inputs;
	set<int>		outputs;
	int				nodeInputDepth;
	int				nodeOutputDepth;
	Value			value;
};

class Input : public CircuitNode {
public:
	Input(int id) : CircuitNode(id) {}

	string getNodeLabel() const { return "(input)"; }
};

class Output : public CircuitNode {
public:
	Output(int nodeId) : CircuitNode(nodeId) {
		nodeInputDepth = nodeOutputDepth = 1;
	}

	string getNodeLabel() const { return "(output)"; }

	Value eval(CryptoContext<ILVector2n>& cc, CircuitGraph& cg) {
		std::cout << "Eval of output node " << nodeId << " by evaluating " << inputs[0] << std::endl;
		return value = cg.getNodeById(inputs[0])->eval(cc, cg);
	}
};

class ModReduceNode : public CircuitNode {
public:
	ModReduceNode(int id, const vector<int>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}

	void setBottomUpDepth() { nodeInputDepth = nodeOutputDepth + 1; }
	string getNodeLabel() const { return "M/R"; }
	bool isModReduce() const { return true; }

	Value eval(CryptoContext<ILVector2n>& cc, CircuitGraph& cg) {
		throw std::logic_error("eval not implemented for ModReduce");
	}
};

class EvalNegNode : public CircuitNode {
public:
	EvalNegNode(int id, const vector<int>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}

	string getNodeLabel() const { return "-"; }

	Value eval(CryptoContext<ILVector2n>& cc, CircuitGraph& cg) {
		throw std::logic_error("eval not implemented for EvalNeg");
	}
};

class EvalAddNode : public CircuitNode {
public:
	EvalAddNode(int id, const vector<int>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}

	string getNodeLabel() const { return "+"; }

	Value eval(CryptoContext<ILVector2n>& cc, CircuitGraph& cg) {
		// gather together all of the inputs to this gate and add them
		if( inputs.size() == 0 ) throw std::logic_error("Cannot add, no inputs");
		else if( inputs.size() == 1 ) return cg.getNodeById( inputs[0] )->getValue();

		shared_ptr<Ciphertext<ILVector2n>> sum = cc.EvalAdd(cg.getNodeById( inputs[0] )->getValue(), cg.getNodeById( inputs[1] )->getValue());

		for( size_t i = 2; i < inputs.size(); i++ )
			sum = cc.EvalAdd(sum, cg.getNodeById( inputs[i] )->getValue());
		return value = sum;
	}
};

class EvalSubNode : public CircuitNode {
public:
	EvalSubNode(int id, const vector<int>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}

	string getNodeLabel() const { return "-"; }

	Value eval(CryptoContext<ILVector2n>& cc, CircuitGraph& cg) {
		// gather together all of the inputs to this gate and subtract them
		if( inputs.size() == 0 ) throw std::logic_error("Cannot subtract, no inputs");
		else if( inputs.size() == 1 ) return cg.getNodeById( inputs[0] )->getValue();

		shared_ptr<Ciphertext<ILVector2n>> prod = cc.EvalMult(cg.getNodeById( inputs[0] )->getValue(), cg.getNodeById( inputs[1] )->getValue());

		for( size_t i = 2; i < inputs.size(); i++ )
			prod = cc.EvalSub(prod, cg.getNodeById( inputs[i] )->getValue());
		return value = prod;
	}
};

class EvalMultNode : public CircuitNode {
public:
	EvalMultNode(int id, const vector<int>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}

	void setBottomUpDepth() { nodeInputDepth = nodeOutputDepth + 1; }
	string getNodeLabel() const { return "*"; }

	Value eval(CryptoContext<ILVector2n>& cc, CircuitGraph& cg) {
		// gather together all of the inputs to this gate and multiply them
		if( inputs.size() == 0 ) throw std::logic_error("Cannot multiply, no inputs");
		else if( inputs.size() == 1 ) return cg.getNodeById( inputs[0] )->getValue();

		shared_ptr<Ciphertext<ILVector2n>> prod = cc.EvalMult(cg.getNodeById( inputs[0] )->getValue(), cg.getNodeById( inputs[1] )->getValue());

		for( size_t i = 2; i < inputs.size(); i++ )
			prod = cc.EvalMult(prod, cg.getNodeById( inputs[i] )->getValue());
		return value = prod;
	}
};

#endif
