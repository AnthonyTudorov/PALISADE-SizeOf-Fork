/**
 * @file circuitnode.h -- Representation of a node in the graph of a circuit
 * @author  TPOC: palisade@njit.edu
 *
 * @section LICENSE
 *
 * Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @section DESCRIPTION
 *
 * This code provides support for representing a node in a circuit
 *
 */

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
#include "palisade.h"
#include "cryptocontext.h"

namespace lbcrypto {

class CircuitSimulation {
public:
	usint	nodeId;
	OpType	op;

	CircuitSimulation(usint id, OpType op) : nodeId(id), op(op) {}
	friend ostream& operator<<(ostream& out, const CircuitSimulation& item) {
		out << item.op << " at Node " << item.nodeId;
		return out;
	}
};

class CircuitGraph;

// This class is used to represent a node in a circuit
// the node can have several inputs, and it has one output
// nodes are identified by a node id
class CircuitNode {
private:
	static	int							step;
	static vector<CircuitSimulation>	sim;

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
	bool IsOutput() const { return is_output; }

	void setAsInput() { is_input = true; }
	void unsetAsInput() { is_input = false; }
	bool IsInput() const { return is_input; }

	const usint getInputDepth() const { return nodeInputDepth; }
	const usint getOutputDepth() const { return nodeOutputDepth; }
	void resetDepth() { this->nodeInputDepth = this->nodeOutputDepth = 0; }
	void setInputDepth(int newDepth) { nodeInputDepth = newDepth; }
	void setOutputDepth(int newDepth) { nodeOutputDepth = newDepth; }
	void resetOutputDepth(int newDepth) { nodeOutputDepth = newDepth; }

	virtual void setBottomUpDepth() { nodeInputDepth = nodeOutputDepth; } // by default, nodeOutputDepth does not change
	virtual bool isModReduce() const { return false; }

	virtual string getNodeLabel() const = 0;
	virtual OpType OpTag() const = 0;

	friend ostream& operator<<(ostream& out, const CircuitNode& n);

	virtual void simeval(CircuitGraph& cg) {} //= 0;

	static void ResetSimulation() {
		step = 0;
		sim.clear();
	}

	void Log(OpType t) {
		sim.push_back( CircuitSimulation(GetId(), t) );
		step++;
	}

	static void PrintOperationSet(ostream& out) {
		map<OpType,bool> ops;
		for( int i=0; i < step; i++ )
			ops[ sim[i].op ] = true;
		for( auto op : ops )
			out << op.first << endl;
	}

	static void PrintLog(ostream& out) {
		out << step << " steps" << endl;
		for( int i=0; i < step; i++ )
			out << i << ": " << sim[i] << endl;
	}

protected:
	bool			is_input;
	bool			is_output;
	usint			nodeId;

	vector<usint>	inputs;
	set<usint>		outputs;
	usint			nodeInputDepth;
	usint			nodeOutputDepth;
};


template<typename Element>
class CircuitGraphWithValues;

// we separate the implementation of the graph from the implementation of the values
template<typename Element>
class CircuitNodeWithValue {
private:
	static	int							step;
	static vector<CircuitSimulation>	sim;

protected:
	CircuitNode		*node;
	Value<Element>	value;
	usint			noiseval;
	usint			timeval;

public:
	CircuitNodeWithValue(CircuitNode *n) : node(n), noiseval(3), timeval(0) {}
	virtual ~CircuitNodeWithValue() {}

	wire_type GetType() const { return value.GetType(); }

	usint GetNoise() const { return noiseval; }
	void SetNoise(usint n) { noiseval = n; }

	CircuitNode *getNode() const { return node; }
	Value<Element>& getValue() { return value; }
	const Value<Element>& getValue() const { return value; }
	void setValue(const Value<Element>& v) { value = v; }
	virtual uint32_t getRuntime() { return 0; }

	usint GetId() const { return node->GetId(); }
	string getNodeLabel() const { return node->getNodeLabel(); }
	OpType OpTag() const { return node->OpTag(); }
	bool isModReduce() const { return node->isModReduce(); }

	virtual Value<Element> eval(CryptoContext<Element>& cc, CircuitGraphWithValues<Element>& cg) { Log(); return value; }

	static void ResetSimulation() {
		step = 0;
		sim.clear();
	}

	void Log() {
		sim.push_back( CircuitSimulation(node->GetId(), node->OpTag()) );
		step++;
	}

	static void PrintLog(ostream& out) {
		out << step << " steps" << endl;
		for( int i=0; i < step; i++ )
			out << i << ": " << sim[i] << endl;
	}

};

template<typename Element>
extern ostream& operator<<(ostream& out, const CircuitNodeWithValue<Element>& n);

template<typename Element>
int	CircuitNodeWithValue<Element>::step;

template<typename Element>
vector<CircuitSimulation> CircuitNodeWithValue<Element>::sim;

template<typename Element>
extern CircuitNodeWithValue<Element> *ValueNodeFactory( CircuitNode *n );

class ConstInput : public CircuitNode {
	usint val;
public:
	ConstInput(usint id, usint value) : CircuitNode(id), val(value) {}

	OpType OpTag() const { return "ConstInput"; }
	string getNodeLabel() const { return "(const)"; }
	usint GetVal() const { return val; }
};

template<typename Element>
class ConstInputWithValue : public CircuitNodeWithValue<Element> {
public:
	ConstInputWithValue(ConstInput* ci) : CircuitNodeWithValue<Element>(ci) {
		this->value = BigBinaryInteger(ci->GetVal());
	}
};

class Input : public CircuitNode {
	wire_type type;
public:
	Input(usint id, wire_type type) : CircuitNode(id), type(type) {
		this->setAsInput();
	}

	OpType OpTag() const { return "Input"; }
	string getNodeLabel() const { return "(input)"; }
	wire_type GetType() const { return type; }
};

template<typename Element>
class InputWithValue : public CircuitNodeWithValue<Element> {
public:
	InputWithValue(Input* in) : CircuitNodeWithValue<Element>(in) {
		this->value.SetType(in->GetType());
	}
};

class Output : public CircuitNode {
public:
	Output(usint nodeId) : CircuitNode(nodeId) {
		this->nodeInputDepth = this->nodeOutputDepth = 1;
	}

	OpType OpTag() const { return "Output"; }
	string getNodeLabel() const { return "(output)"; }
};

template<typename Element>
class OutputWithValue : public CircuitNodeWithValue<Element> {
public:
	OutputWithValue(Output* out) : CircuitNodeWithValue<Element>(out) {}

	Value<Element> eval(CryptoContext<Element>& cc, CircuitGraphWithValues<Element>& cg) {
		std::cout << "Eval of output node " << this->GetId() << " by evaluating " << this->getNode()->getInputs()[0] << std::endl;
		return this->value = cg.getNodeById(this->getNode()->getInputs()[0])->eval(cc, cg);
	}
};

class ModReduceNode : public CircuitNode {
public:
	ModReduceNode(usint id, const vector<usint>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}

	void setBottomUpDepth() { this->nodeInputDepth = this->nodeOutputDepth + 1; }
	OpType OpTag() const { return OpModReduce; }
	string getNodeLabel() const { return "M/R"; }
	bool isModReduce() const { return true; }
};

template<typename Element>
class ModReduceNodeWithValue : public CircuitNodeWithValue<Element> {
public:
	ModReduceNodeWithValue(ModReduceNode* node) : CircuitNodeWithValue<Element>(node) {}

	Value<Element> eval(CryptoContext<Element>& cc, CircuitGraphWithValues<Element>& cg);
};

class EvalNegNode : public CircuitNode {
public:
	EvalNegNode(usint id, const vector<usint>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}

	OpType OpTag() const { return OpEvalNeg; }
	string getNodeLabel() const { return "-"; }
};

template<typename Element>
class EvalNegNodeWithValue : public CircuitNodeWithValue<Element> {
public:
	EvalNegNodeWithValue(EvalNegNode* node) : CircuitNodeWithValue<Element>(node) {}

	Value<Element> eval(CryptoContext<Element>& cc, CircuitGraphWithValues<Element>& cg) {
		throw std::logic_error("eval not implemented for EvalNeg");
	}
};

class EvalAddNode : public CircuitNode {
public:
	EvalAddNode(usint id, const vector<usint>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}

	OpType OpTag() const { return OpEvalAdd; }
	string getNodeLabel() const { return "+"; }
};

template<typename Element>
class EvalAddNodeWithValue : public CircuitNodeWithValue<Element> {
public:
	EvalAddNodeWithValue(EvalAddNode* node) : CircuitNodeWithValue<Element>(node) {}

	Value<Element> eval(CryptoContext<Element>& cc, CircuitGraphWithValues<Element>& cg);
};

class EvalSubNode : public CircuitNode {
public:
	EvalSubNode(usint id, const vector<usint>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}

	OpType OpTag() const { return OpEvalSub; }
	string getNodeLabel() const { return "-"; }
};

template<typename Element>
class EvalSubNodeWithValue : public CircuitNodeWithValue<Element> {
public:
	EvalSubNodeWithValue(EvalSubNode* node) : CircuitNodeWithValue<Element>(node) {}

	Value<Element> eval(CryptoContext<Element>& cc, CircuitGraphWithValues<Element>& cg);
};

class EvalMultNode : public CircuitNode {
public:
	EvalMultNode(usint id, const vector<usint>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}

	void setBottomUpDepth() { this->nodeInputDepth = this->nodeOutputDepth + 1; }
	OpType OpTag() const { return OpEvalMult; }
	string getNodeLabel() const { return "*"; }
};

template<typename Element>
class EvalMultNodeWithValue : public CircuitNodeWithValue<Element> {
public:
	EvalMultNodeWithValue(EvalMultNode* node) : CircuitNodeWithValue<Element>(node) {}

	Value<Element> eval(CryptoContext<Element>& cc, CircuitGraphWithValues<Element>& cg);
};

}

#endif
