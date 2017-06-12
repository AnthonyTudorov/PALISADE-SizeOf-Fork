#ifndef CIRCUITNODE_H
#define CIRCUITNODE_H

#include <string>
#include <vector>
#include <map>
#include <queue>
#include <set>
#include <iostream>
#include <typeinfo>
#include <fstream>
#include <iomanip>
using namespace std;

#include "value.h"
#include "circuitgraph.h"
#include "palisade.h"
#include "cryptocontext.h"

namespace lbcrypto {

class CircuitSimulation {
	usint	nodeId;
	string	stepTag;
public:
	CircuitSimulation(usint id, string tag) : nodeId(id), stepTag(tag) {}
	friend ostream& operator<<(ostream& out, const CircuitSimulation& item) {
		out << item.stepTag << " at Node " << item.nodeId;
		return out;
	}
};

// This class is used to represent a node in a circuit
// the node can have several inputs, and it has one output
// nodes are identified by a node id
class CircuitNode {

public:
	CircuitNode(usint nodeID) {
		this->nodeId = nodeID;
		this->nodeInputDepth = this->nodeOutputDepth = 0;
		is_input = is_output = false;
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

	void setAsInput() { is_input = true; }
	void unsetAsInput() { is_input = false; }

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

	virtual string OpTag() const = 0;

	static void ResetSimulation() {
		step = 0;
		sim.clear();
	}
	void Log() {
		sim.push_back( CircuitSimulation(nodeId, OpTag()) );
		step++;
	}
	static void PrintLog(ostream& out) {
		out << step << " steps" << endl;
		for( size_t i=0; i < step; i++ )
			out << i << ": " << sim[i] << endl;
	}

	virtual Value eval(CryptoContext<ILDCRT2n>& cc, CircuitGraph& cg) { Log(); return value; }

	friend ostream& operator<<(ostream& out, const CircuitNode& n);

protected:
	bool			is_input;
	bool			is_output;
	usint			nodeId;

	vector<usint>	inputs;
	set<usint>		outputs;
	usint			nodeInputDepth;
	usint			nodeOutputDepth;
	Value			value;

private:
	static	int							step;
	static vector<CircuitSimulation>	sim;
};

class ConstInput : public CircuitNode {
public:
	ConstInput(usint id, usint value) : CircuitNode(id) {
		this->value = BigBinaryInteger(value);
	}

	string OpTag() const { return "ConstInput"; }
	string getNodeLabel() const { return "(const)"; }
};

class Input : public CircuitNode {
public:
	Input(usint id, wire_type type) : CircuitNode(id) {
		setAsInput();
		value.SetType(type);
	}

	string OpTag() const { return "Input"; }
	string getNodeLabel() const { return "(input)"; }
};

class Output : public CircuitNode {
public:
	Output(usint nodeId) : CircuitNode(nodeId) {
		nodeInputDepth = nodeOutputDepth = 1;
	}

	string OpTag() const { return "Output"; }
	string getNodeLabel() const { return "(output)"; }

	Value eval(CryptoContext<ILDCRT2n>& cc, CircuitGraph& cg) {
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
	string OpTag() const { return "ModReduce"; }
	string getNodeLabel() const { return "M/R"; }
	bool isModReduce() const { return true; }

	Value eval(CryptoContext<ILDCRT2n>& cc, CircuitGraph& cg);
};

class EvalNegNode : public CircuitNode {
public:
	EvalNegNode(usint id, const vector<usint>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}

	string OpTag() const { return "EvalNeg"; }
	string getNodeLabel() const { return "-"; }

	Value eval(CryptoContext<ILDCRT2n>& cc, CircuitGraph& cg) {
		throw std::logic_error("eval not implemented for EvalNeg");
	}
};

class EvalAddNode : public CircuitNode {
public:
	EvalAddNode(usint id, const vector<usint>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}

	string OpTag() const { return "EvalAdd"; }
	string getNodeLabel() const { return "+"; }

	Value eval(CryptoContext<ILDCRT2n>& cc, CircuitGraph& cg);
};

class EvalSubNode : public CircuitNode {
public:
	EvalSubNode(usint id, const vector<usint>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}

	string OpTag() const { return "EvalSub"; }
	string getNodeLabel() const { return "-"; }

	Value eval(CryptoContext<ILDCRT2n>& cc, CircuitGraph& cg);
};

class EvalMultNode : public CircuitNode {
public:
	EvalMultNode(usint id, const vector<usint>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}

	void setBottomUpDepth() { nodeInputDepth = nodeOutputDepth + 1; }
	string OpTag() const { return "EvalMult"; }
	string getNodeLabel() const { return "*"; }

	Value eval(CryptoContext<ILDCRT2n>& cc, CircuitGraph& cg);
};

}

#endif
