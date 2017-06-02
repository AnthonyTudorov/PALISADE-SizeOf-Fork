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

namespace lbcrypto {

// This class is meant to represent a node in a circuit
// the node can have several inputs, and it has one output
// nodes are identified by a node id
class CircuitNode {

public:
	CircuitNode(usint nodeID) {
		this->nodeId = nodeID;
		this->nodeInputDepth = this->nodeOutputDepth = 0;
		is_output = false;
	}
	virtual ~CircuitNode() {}

	usint GetId() const { return nodeId; }

	const vector<usint>& getInputs() const { return inputs; }
	int getInput(usint i) { return inputs[i]; }
	void setInput(usint inputIdx, usint nodeId) { inputs[inputIdx] = nodeId; }

	const set<usint>& getOutputs() const { return outputs; }
	void addOutput(usint n) { outputs.insert(n); }
	void delOutput(usint n) { outputs.erase(n); }

	void setAsOutput() { is_output = true; }
	void unsetAsOutput() { is_output = false; }

	const usint getInputDepth() const { return nodeInputDepth; }
	const usint getOutputDepth() const { return nodeOutputDepth; }
	void resetDepth() { this->nodeInputDepth = this->nodeOutputDepth = 0; }
	void setInputDepth(int newDepth) { nodeInputDepth = newDepth; }
	void setOutputDepth(int newDepth) { nodeOutputDepth = newDepth; }
	void resetOutputDepth(int newDepth) { nodeOutputDepth = newDepth; }

	wire_type GetType() const { return value.GetType(); }

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
	usint			nodeId;

	vector<usint>		inputs;
	set<usint>		outputs;
	usint				nodeInputDepth;
	usint				nodeOutputDepth;
	Value			value;
};

class ConstInput : public CircuitNode {
public:
	ConstInput(usint id, usint value) : CircuitNode(id) {
		this->value = BigBinaryInteger(value);
	}

	string getNodeLabel() const { return "(const)"; }
};

class Input : public CircuitNode {
public:
	Input(usint id, wire_type type) : CircuitNode(id) {
		value.SetType(type);
	}

	string getNodeLabel() const { return "(input)"; }
};

class Output : public CircuitNode {
public:
	Output(usint nodeId) : CircuitNode(nodeId) {
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
	ModReduceNode(usint id, const vector<usint>& inputs) : CircuitNode(id) {
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
	EvalNegNode(usint id, const vector<usint>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}

	string getNodeLabel() const { return "-"; }

	Value eval(CryptoContext<ILVector2n>& cc, CircuitGraph& cg) {
		throw std::logic_error("eval not implemented for EvalNeg");
	}
};

class EvalAddNode : public CircuitNode {
public:
	EvalAddNode(usint id, const vector<usint>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}

	string getNodeLabel() const { return "+"; }

	Value eval(CryptoContext<ILVector2n>& cc, CircuitGraph& cg);
};

class EvalSubNode : public CircuitNode {
public:
	EvalSubNode(usint id, const vector<usint>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}

	string getNodeLabel() const { return "-"; }

	Value eval(CryptoContext<ILVector2n>& cc, CircuitGraph& cg);
};

class EvalMultNode : public CircuitNode {
public:
	EvalMultNode(usint id, const vector<usint>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}

	void setBottomUpDepth() { nodeInputDepth = nodeOutputDepth + 1; }
	string getNodeLabel() const { return "*"; }

	Value eval(CryptoContext<ILVector2n>& cc, CircuitGraph& cg);
};

}

#endif
