#ifndef CIRCUITNODE_H
#define CIRCUITNODE_H

#include "CircuitSim.h"

#include <string>
#include <vector>
#include <map>
#include <queue>
#include <set>
#include <iostream>
#include <typeinfo>

#include "../Util/Value.h"
using std::string;
using std::vector;
using std::map;
using std::queue;
using std::set;
using std::ostream;

class CircuitNode {
public:
	CircuitNode(string name, int inputCount) {
		this->inputs.resize(inputCount, 0);
		this->name = name;
		this->nodeInputDepth = this->nodeOutputDepth = 0;
		is_output = false;
	}

	virtual ~CircuitNode() {}

	virtual CircuitNode *clone(string name, int inputCount) { return new CircuitNode(name, inputCount); }

	CircuitNode * getInput(int i) { return inputs[i]; }
	void setInput(int inputIdx, CircuitNode *node) { inputs[inputIdx] = node; }
	const vector<CircuitNode *>& getInputs() const { return inputs; }

	void addOutput(string n) { outputs.insert(n); }
	void delOutput(string n) { outputs.erase(n); }
	void renameOutput( string oldO, string newO ) { delOutput(oldO); addOutput(newO); }
	const set<string>& getOutputs() const { return outputs; }

	void setAsOutput() { is_output = true; }
	void unsetAsOutput() { is_output = false; }

	static CircuitNode *NodeFactory(string op, vector<CircuitNode *> args, string name = "");

	const int getInputDepth() const { return nodeInputDepth; }
	const int getOutputDepth() const { return nodeOutputDepth; }
	void resetDepth() { this->nodeInputDepth = this->nodeOutputDepth = 0; }
	void setInputDepth(int newDepth) { nodeInputDepth = newDepth; }
	void setOutputDepth(int newDepth) { nodeOutputDepth = newDepth; }
	void resetOutputDepth(int newDepth) { nodeOutputDepth = newDepth; }

	string getName() const { return name; }
	void setName(string s) { name = s; }

	Value& getValue() { return value; }
	const Value& getValue() const { return value; }
	void setValue(const Value& v) { value = v; }

	void processNodeDepth(CircuitGraph*);
	void processNodeDepth(CircuitGraph*, queue<CircuitNode*>&);

	virtual void setBottomUpDepth() { nodeInputDepth = nodeOutputDepth; } // by default, nodeOutputDepth does not change
	virtual string getNodeLabel() const { return "<none>"; }
	virtual string getNodeDecoration() const { return name; }
	virtual bool isModReduce() const { return false; }

	virtual uint32_t getRuntime() { return 0; }

	virtual Value eval() { std::cerr << "no way today!!! " << typeid(this).name() << std::endl; return 0; }

	friend ostream& operator<<(ostream& out, const CircuitNode& n);

	static string generateNodeName() { return "node" + std::to_string( ++generatedNameCounter ); }

private:
	static int	generatedNameCounter;

protected:

	bool			is_output;
	string						name;
	vector<CircuitNode*>		inputs;
	set<string>		outputs;
	int				nodeInputDepth;
	int				nodeOutputDepth;
	Value			value;
};

class Input : public CircuitNode {
public:
	Input(string name) : CircuitNode(name, 0) {}

	CircuitNode *clone(string name, int inputCount) { return new Input(name); }
	string getNodeLabel() const { return name; }
	string getNodeDecoration() const { return ""; }

	Value eval() {
		return value;
	}
};

class UnaryOp : public CircuitNode {
public:
	UnaryOp(string name, CircuitNode *op1) : CircuitNode(name, 1) {
		setInput(0, op1);
		op1->addOutput(name);
	}

protected:
	UnaryOp(string name) : CircuitNode(name, 1) {}
};

class BinaryOp : public CircuitNode {
public:
	BinaryOp(string name, CircuitNode *op1, CircuitNode *op2) : CircuitNode(name, 2) {
		setInput(0, op1);
		setInput(1, op2);
		op1->addOutput(name);
		op2->addOutput(name);
	}

protected:
	BinaryOp(string name) : CircuitNode(name, 2) {}
};

class Output : public UnaryOp {
public:
	Output(string name, CircuitNode *op1) : UnaryOp(name, op1) {
		nodeInputDepth = nodeOutputDepth = 1;
	}

	CircuitNode *clone(string name, int inputCount) { return new Output(name); }
	string getNodeLabel() const { return name + " \\n(output)"; }
	string getNodeDecoration() const { return ""; }

private:
	Output(string name) : UnaryOp(name) {}
};

class ModReduceNode : public UnaryOp {
public:
	ModReduceNode(string name, CircuitNode *op1) : UnaryOp(name, op1) {}

	CircuitNode *clone(string name, int inputCount) { return new ModReduceNode(name); }

	void setBottomUpDepth() { nodeInputDepth = nodeOutputDepth + 1; }
	string getNodeLabel() const { return "M/R"; }
	bool isModReduce() const { return true; }
	string getNodeDecoration() const { return ""; }

	Value eval() {
		return value = inputs[0]->eval();
	}

private:
	ModReduceNode(string name) : UnaryOp(name) {}
};

class EvalNegNode : public UnaryOp {
public:
	EvalNegNode(string name, CircuitNode *op1) : UnaryOp(name, op1) {}

	CircuitNode *clone(string name, int inputCount) { return new EvalNegNode(name); }

	string getNodeLabel() const { return "-"; }

	Value eval() {
		return value = EvalNeg(inputs[0]->eval());
	}

private:
	EvalNegNode(string name) : UnaryOp(name) {}
};

class EvalAddNode : public BinaryOp {
public:
	EvalAddNode(string name, CircuitNode *op1, CircuitNode *op2) : BinaryOp(name, op1, op2) {}

	CircuitNode *clone(string name, int inputCount) { return new EvalAddNode(name); }

	string getNodeLabel() const { return "+"; }

	Value eval() {
		return value = EvalAdd(inputs[0]->eval(), inputs[1]->eval());
	}

private:
	EvalAddNode(string name) : BinaryOp(name) {}
};

class EvalMultNode : public BinaryOp {
public:
	EvalMultNode(string name, CircuitNode *op1, CircuitNode *op2) : BinaryOp(name, op1, op2) {}

	CircuitNode *clone(string name, int inputCount) { return new EvalMultNode(name); }

	void setBottomUpDepth() { nodeInputDepth = nodeOutputDepth + 1; }
	string getNodeLabel() const { return "*"; }

	Value eval() {
		return value = EvalMult(inputs[0]->eval(), inputs[1]->eval());
	}

private:
	EvalMultNode(string name) : BinaryOp(name) {}
};

#endif
