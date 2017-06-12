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
template<typename Element>
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

	Value<Element>& getValue() { return value; }
	const Value<Element>& getValue() const { return value; }
	void setValue(const Value<Element>& v) { value = v; }

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

	virtual Value<Element> eval(CryptoContext<Element>& cc, CircuitGraph<Element>& cg) { Log(); return value; }

protected:
	bool			is_input;
	bool			is_output;
	usint			nodeId;

	vector<usint>	inputs;
	set<usint>		outputs;
	usint			nodeInputDepth;
	usint			nodeOutputDepth;
	Value<Element>	value;

private:
	static	int							step;
	static vector<CircuitSimulation>	sim;
};

template<typename Element>
ostream& operator<<(ostream& out, const CircuitNode<Element>& n);


template<typename Element>
class ConstInput : public CircuitNode<Element> {
public:
	ConstInput(usint id, usint value) : CircuitNode<Element>(id) {
		this->value = BigBinaryInteger(value);
	}

	string OpTag() const { return "ConstInput"; }
	string getNodeLabel() const { return "(const)"; }
};

template<typename Element>
class Input : public CircuitNode<Element> {
public:
	Input(usint id, wire_type type) : CircuitNode<Element>(id) {
		this->setAsInput();
		this->value.SetType(type);
	}

	string OpTag() const { return "Input"; }
	string getNodeLabel() const { return "(input)"; }
};

template<typename Element>
class Output : public CircuitNode<Element> {
public:
	Output(usint nodeId) : CircuitNode<Element>(nodeId) {
		this->nodeInputDepth = this->nodeOutputDepth = 1;
	}

	string OpTag() const { return "Output"; }
	string getNodeLabel() const { return "(output)"; }

	Value<Element> eval(CryptoContext<Element>& cc, CircuitGraph<Element>& cg) {
		std::cout << "Eval of output node " << this->nodeId << " by evaluating " << this->inputs[0] << std::endl;
		return this->value = cg.getNodeById(this->inputs[0])->eval(cc, cg);
	}
};

template<typename Element>
class ModReduceNode : public CircuitNode<Element> {
public:
	ModReduceNode(usint id, const vector<usint>& inputs) : CircuitNode<Element>(id) {
		this->inputs = inputs;
	}

	void setBottomUpDepth() { this->nodeInputDepth = this->nodeOutputDepth + 1; }
	string OpTag() const { return "ModReduce"; }
	string getNodeLabel() const { return "M/R"; }
	bool isModReduce() const { return true; }

	Value<Element> eval(CryptoContext<Element>& cc, CircuitGraph<Element>& cg);
};

template<typename Element>
class EvalNegNode : public CircuitNode<Element> {
public:
	EvalNegNode(usint id, const vector<usint>& inputs) : CircuitNode<Element>(id) {
		this->inputs = inputs;
	}

	string OpTag() const { return "EvalNeg"; }
	string getNodeLabel() const { return "-"; }

	Value<Element> eval(CryptoContext<Element>& cc, CircuitGraph<Element>& cg) {
		throw std::logic_error("eval not implemented for EvalNeg");
	}
};

template<typename Element>
class EvalAddNode : public CircuitNode<Element> {
public:
	EvalAddNode(usint id, const vector<usint>& inputs) : CircuitNode<Element>(id) {
		this->inputs = inputs;
	}

	string OpTag() const { return "EvalAdd"; }
	string getNodeLabel() const { return "+"; }

	Value<Element> eval(CryptoContext<Element>& cc, CircuitGraph<Element>& cg);
};

template<typename Element>
class EvalSubNode : public CircuitNode<Element> {
public:
	EvalSubNode(usint id, const vector<usint>& inputs) : CircuitNode<Element>(id) {
		this->inputs = inputs;
	}

	string OpTag() const { return "EvalSub"; }
	string getNodeLabel() const { return "-"; }

	Value<Element> eval(CryptoContext<Element>& cc, CircuitGraph<Element>& cg);
};

template<typename Element>
class EvalMultNode : public CircuitNode<Element> {
public:
	EvalMultNode(usint id, const vector<usint>& inputs) : CircuitNode<Element>(id) {
		this->inputs = inputs;
	}

	void setBottomUpDepth() { this->nodeInputDepth = this->nodeOutputDepth + 1; }
	string OpTag() const { return "EvalMult"; }
	string getNodeLabel() const { return "*"; }

	Value<Element> eval(CryptoContext<Element>& cc, CircuitGraph<Element>& cg);
};

}

#endif
