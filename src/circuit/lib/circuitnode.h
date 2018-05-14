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

#include "palisade.h"
#include "cryptocontext.h"
#include "circuitvalue.h"

namespace lbcrypto {

struct CircuitSimulation {
	usint	nodeId;
	OpType	op;

	CircuitSimulation(usint id, OpType op) : nodeId(id), op(op) {}
	friend ostream& operator<<(ostream& out, const CircuitSimulation& item) {
		out << item.op << " at Node " << item.nodeId;
		return out;
	}
};


static const usint DEFAULTNOISEVAL = 3;

class CircuitGraph;

extern bool CircuitOpTrace;

// A CircuitNode represents a node in a circuit
// Each node may have several inputs, and has one output
// Nodes are identified by a node id
class CircuitNode {
public:
	CircuitNode(usint nodeID) {
		this->nodeId = nodeID;
		is_input = is_output = false;
	}
	virtual ~CircuitNode() {}

	usint GetId() const { return nodeId; }

	const vector<usint>& getInputs() const { return inputs; }
	int getInput(usint i) { return inputs[i]; }
	void setInput(usint inputIdx, usint nodeId) { inputs[inputIdx] = nodeId; }

	const vector<usint>& getOutputs() const { return outputs; }
	void addOutput(usint n) { outputs.push_back(n); }
	void delOutput(usint n) {
		auto it = std::find( outputs.begin(), outputs.end(), n);
		if( it != outputs.end() )
			outputs.erase(it);
	}

	void setAsOutput() { is_output = true; }
	void unsetAsOutput() { is_output = false; }
	bool IsOutput() const { return is_output; }

	void setAsInput() { is_input = true; }
	void unsetAsInput() { is_input = false; }
	bool IsInput() const { return is_input; }

protected:
	CircuitNode(CircuitNode *n) { CopyValues(n); }

	virtual void CopyValues(CircuitNode *n) {
		this->is_input = n->is_input;
		this->is_output = n->is_output;
		this->nodeId = n->nodeId;
		this->inputs = n->inputs;
		this->outputs = n->outputs;
	}

	bool				is_input;
	bool				is_output;
	usint			nodeId;

	vector<usint>	inputs;
	vector<usint>	outputs;
};

template<typename Element>
class CircuitGraphWithValues;

enum EvaluateMode {
	GetOperationsList,			// gather a list of operations that will be performed
	Evaluate,					// actually perform the calculations
	CalculateRuntimeEstimates,	// sum up estimates up the chain
};

// we separate the implementation of the graph from the implementation of the values
template<typename Element>
class CircuitNodeWithValue : public CircuitNode {
private:
	static	int							step;

protected:
	CircuitValue<Element>	value;
	usint			noiseval;
	bool				visited;
	int				evalsequence;

	int			nodeInputDepth;
	int			nodeOutputDepth;

	double			runtimeEstimateNode;
	double			runtimeEstimateCumulative;
	double			runtimeActual;
	double			noisevalEstimate;
	double			noisevalActual;

	static	map<usint,map<TimingStatisticsKey,int>>	opcountByNode;

public:
	CircuitNodeWithValue(CircuitNode *n) : CircuitNode(n) {
		Reset();
	}

	virtual ~CircuitNodeWithValue() {}

	static CircuitNodeWithValue<Element> *ValueNodeFactory( CircuitNode *n );
	static map<usint,map<TimingStatisticsKey,int>>& GetOperationsMap();

	wire_type GetType() const { return value.GetType(); }

	const int getInputDepth() const { return nodeInputDepth; }
	const int getOutputDepth() const { return nodeOutputDepth; }
	void resetDepth() { this->nodeInputDepth = this->nodeOutputDepth = 0; }
	void setInputDepth(int newDepth) { nodeInputDepth = newDepth; }
	void setOutputDepth(int newDepth) { nodeOutputDepth = newDepth; }
	void resetOutputDepth(int newDepth) { nodeOutputDepth = newDepth; }

	virtual void setBottomUpDepth() { nodeInputDepth = nodeOutputDepth; } // by default, nodeOutputDepth does not change

	double GetNoiseEstimate() const { return noisevalEstimate; }
	void SetNoiseEstimate(double n) { noisevalEstimate = n; }
	double GetNoiseActual() const { return noisevalActual; }
	void SetNoiseActual(double n) { noisevalActual = n; }

	double GetRuntimeEstimateNode() const { return runtimeEstimateNode; }
	void SetRuntimeEstimateNode(double n) { runtimeEstimateNode = n; }
	double GetRuntimeEstimate() const { return runtimeEstimateCumulative; }
	void SetRuntimeEstimate(double n) { runtimeEstimateCumulative = n; }
	double GetRuntimeActual() const { return runtimeActual; }

	CircuitValue<Element>& getValue() { return value; }
	const CircuitValue<Element>& getValue() const { return value; }
	void setValue(const CircuitValue<Element>& v) { value = v; }

	// Each node needs to identify the operations that it performs,
	// and in which order
	virtual const vector<OpType>& GetOperationsSequence() const {
		static vector<OpType> empty;
		return empty;
	}

	// this method is a wrapper for all of the operations that might be performed
	// on this node. The first argument determines the operation
	CircuitValue<Element> Evaluate(
			EvaluateMode mode,
			CryptoContext<Element> cc,
			CircuitGraphWithValues<Element>& cg) {

		if( Visited() )
			return this->value;
		Visit();

		this->evalsequence = ++step;
		TimeVar t;
		TIC(t);
		this->eval(mode,cc,cg);
		if( mode == EvaluateMode::Evaluate )
			this->runtimeActual = TOC_MS(t);

		return this->value;
	}

	virtual void eval(EvaluateMode mode, CryptoContext<Element> cc, CircuitGraphWithValues<Element>& cg) = 0;

	virtual OpType OpTag() const = 0;
	virtual string getNodeLabel() const { return ""; }

	virtual bool isModReduce() const { return false; }

private:
	void Reset() {
		noisevalEstimate = 0;
		noisevalActual = DEFAULTNOISEVAL;
		runtimeEstimateNode = runtimeEstimateCumulative = runtimeActual = 0;
		this->nodeInputDepth = this->nodeOutputDepth = 0;
		visited = false;
		evalsequence = -1;
		if( IsInput() == false && value.GetType() != UNKNOWN ) {
			value = CircuitValue<Element>();
		}
	}

public:
	bool Visited() const { return visited; }
	const void Visit() { visited = true; }
	const void ClearVisit() { visited = false; }

	int GetEvalSequenceNumber() const { return evalsequence; }

	friend ostream& operator<<(ostream& out, CircuitNodeWithValue<Element>& n) {
		out << n.GetId() << "  [label=\"" << n.GetId() << "\\n";
		if( n.getInputDepth() != 0 )
			out << "(d=" << n.getInputDepth() << ")\\n";
		out << n.getNodeLabel();
		if( n.IsOutput() ) {
			out << "(output)\\n";
		}

		if( n.GetNoiseActual() != 0 )
			out << "\\n(noise=" << n.GetNoiseActual() << ")\\n";

		const CircuitValue<Element>& val = n.getValue();
		if( val.GetType() != UNKNOWN ) {
			out << val;
		}

		out << "\"]; ";

		const vector<usint>& nodeInputs = n.getInputs();
		for( usint input : nodeInputs )
			out << input << " -> " << n.GetId() << "; ";

		return out;
	}

};

class Input : public CircuitNode {
	wire_type type;

protected:
	void CopyValues(CircuitNode *n) {
		Input& nn = dynamic_cast<Input&>( *n );
		this->type = nn.type;
		CircuitNode::CopyValues(n);
	}

public:
	Input(usint id, wire_type type) : CircuitNode(id), type(type) {
		this->setAsInput();
	}

	wire_type GetType() const { return type; }
};

template<typename Element>
class InputWithValue : public CircuitNodeWithValue<Element> {
public:
	InputWithValue(CircuitNode* in) : CircuitNodeWithValue<Element>(in) {
		Input& nn = dynamic_cast<Input&>( *in );
		this->value.SetType(nn.GetType());
	}

	OpType OpTag() const { return OpNOOP; }
	string getNodeLabel() const { return "(input)"; }

	void eval(EvaluateMode mode, CryptoContext<Element> cc, CircuitGraphWithValues<Element>& cg) {
		if( mode == CalculateRuntimeEstimates )
			this->SetNoiseEstimate(DEFAULTNOISEVAL);
		return;
	}
};

class ConstInt : public CircuitNode {
	int64_t val;

protected:
	void CopyValues(CircuitNode *n) {
		ConstInt& nn = dynamic_cast<ConstInt&>( *n );
		this->val = nn.val;
		CircuitNode::CopyValues(n);
	}

public:
	ConstInt(usint id, int64_t val) : CircuitNode(id), val(val) {
		this->setAsInput();
	}

	wire_type GetType() const { return INT; }
	int64_t GetInt() const { return val; }
};

template<typename Element>
class ConstIntWithValue : public CircuitNodeWithValue<Element> {
public:
	ConstIntWithValue(CircuitNode* in) : CircuitNodeWithValue<Element>(in) {
		ConstInt& nn = dynamic_cast<ConstInt&>( *in );
		this->value = CircuitValue<Element>(nn.GetInt());
	}

	OpType OpTag() const { return OpNOOP; }
	string getNodeLabel() const { return "(const int)"; }

	void eval(EvaluateMode mode, CryptoContext<Element> cc, CircuitGraphWithValues<Element>& cg) {
		if( mode == CalculateRuntimeEstimates )
			this->SetNoiseEstimate(DEFAULTNOISEVAL);
		return;
	}
};

class ConstPtxt : public CircuitNode {
	int64_t val;

protected:
	void CopyValues(CircuitNode *n) {
		ConstPtxt& nn = dynamic_cast<ConstPtxt&>( *n );
		this->val = nn.val;
		CircuitNode::CopyValues(n);
	}

public:
	ConstPtxt(usint id, int64_t val) : CircuitNode(id),val(val) {
		this->setAsInput();
	}

	wire_type GetType() const { return PLAINTEXT; }
	int64_t GetInt() const { return val; }
};

template<typename Element>
class ConstPtxtWithValue : public CircuitNodeWithValue<Element> {
public:
	ConstPtxtWithValue(CircuitNode* in) : CircuitNodeWithValue<Element>(in) {
		ConstInt& nn = dynamic_cast<ConstInt&>( *in );
		this->setValue(nn.GetInt());
	}
	OpType OpTag() const { return OpNOOP; }
	string getNodeLabel() const { return "(const plaintext)"; }

	void eval(EvaluateMode mode, CryptoContext<Element> cc, CircuitGraphWithValues<Element>& cg) {
		if( mode == CalculateRuntimeEstimates )
			this->SetNoiseEstimate(DEFAULTNOISEVAL);
		return;
	}
};

class ModReduceNode : public CircuitNode {
public:
	ModReduceNode(usint id, const vector<usint>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}
};

template<typename Element>
class ModReduceNodeWithValue : public CircuitNodeWithValue<Element> {
public:
	ModReduceNodeWithValue(CircuitNode* node) : CircuitNodeWithValue<Element>(node) {}

	const vector<OpType>& GetOperationsSequence() const {
		static vector<OpType> ops({OpModReduce});
		return ops;
	}

	OpType OpTag() const { return OpModReduce; }
	string getNodeLabel() const { return "M/R"; }

	void setBottomUpDepth() { this->nodeInputDepth = this->nodeOutputDepth + 1; }

	void eval(EvaluateMode mode, CryptoContext<Element> cc, CircuitGraphWithValues<Element>& cg);

	bool isModReduce() const { return true; }
};

class EvalAddNode : public CircuitNode {
public:
	EvalAddNode(usint id, const vector<usint>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}
};

template<typename Element>
class EvalAddNodeWithValue : public CircuitNodeWithValue<Element> {
public:
	EvalAddNodeWithValue(CircuitNode* node) : CircuitNodeWithValue<Element>(node) {}

	const vector<OpType>& GetOperationsSequence() const {
		static vector<OpType> ops({OpEvalAdd});
		return ops;
	}

	OpType OpTag() const { return OpEvalAdd; }
	string getNodeLabel() const { return "+"; }

	void eval(EvaluateMode mode, CryptoContext<Element> cc, CircuitGraphWithValues<Element>& cg);
};

class EvalSubNode : public CircuitNode {
public:
	EvalSubNode(usint id, const vector<usint>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}
};

template<typename Element>
class EvalSubNodeWithValue : public CircuitNodeWithValue<Element> {
public:
	EvalSubNodeWithValue(CircuitNode* node) : CircuitNodeWithValue<Element>(node) {}

	const vector<OpType>& GetOperationsSequence() const {
		static vector<OpType> ops({OpEvalSub});
		return ops;
	}

	OpType OpTag() const { return OpEvalSub; }
	string getNodeLabel() const { return "-"; }

	void eval(EvaluateMode mode, CryptoContext<Element> cc, CircuitGraphWithValues<Element>& cg);
};

class EvalMultNode : public CircuitNode {
public:
	EvalMultNode(usint id, const vector<usint>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}
};

template<typename Element>
class EvalMultNodeWithValue : public CircuitNodeWithValue<Element> {
public:
	EvalMultNodeWithValue(CircuitNode* node) : CircuitNodeWithValue<Element>(node) {}

	const vector<OpType>& GetOperationsSequence() const {
		static vector<OpType> ops({OpEvalMult});
		return ops;
	}

	OpType OpTag() const { return OpEvalMult; }
	string getNodeLabel() const { return "*"; }

	void setBottomUpDepth() { this->nodeInputDepth = this->nodeOutputDepth + 1; }

	void eval(EvaluateMode mode, CryptoContext<Element> cc, CircuitGraphWithValues<Element>& cg);
};

class EvalRShiftNode : public CircuitNode {
public:
	EvalRShiftNode(usint id, const vector<usint>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}
};

template<typename Element>
class EvalRShiftNodeWithValue : public CircuitNodeWithValue<Element> {
public:
	EvalRShiftNodeWithValue(CircuitNode* node) : CircuitNodeWithValue<Element>(node) {}

	const vector<OpType>& GetOperationsSequence() const {
		static vector<OpType> ops({OpEvalRightShift});
		return ops;
	}

	OpType OpTag() const { return OpEvalRightShift; }
	string getNodeLabel() const { return ">>"; }

	void setBottomUpDepth() { this->nodeInputDepth = this->nodeOutputDepth + 1; }

	void eval(EvaluateMode mode, CryptoContext<Element> cc, CircuitGraphWithValues<Element>& cg);
};

class EvalInnerProdNode : public CircuitNode {
public:
	EvalInnerProdNode(usint id, const vector<usint>& inputs) : CircuitNode(id) {
		this->inputs = inputs;
	}
};

template<typename Element>
class EvalInnerProdNodeWithValue : public CircuitNodeWithValue<Element> {
public:
	EvalInnerProdNodeWithValue(CircuitNode* node) : CircuitNodeWithValue<Element>(node) {}

	const vector<OpType>& GetOperationsSequence() const {
		static vector<OpType> ops({OpEvalMerge,OpEvalMerge,OpEvalInnerProduct});
		return ops;
	}

	OpType OpTag() const { return OpEvalInnerProduct; }
	string getNodeLabel() const { return "o"; }

	void setBottomUpDepth() { this->nodeInputDepth = this->nodeOutputDepth + 1; }

	void eval(EvaluateMode mode, CryptoContext<Element> cc, CircuitGraphWithValues<Element>& cg);
};

}

#endif
