/**
 * @file circuitgraph.h -- Representation of a circuit as a graph of circuit nodes.
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
 * This code provides support for representing a circuit as a graph of CircuitNode objects.
 *
 */

#ifndef SRC_CIRCUIT_CIRCUITGRAPH_H_
#define SRC_CIRCUIT_CIRCUITGRAPH_H_

#include <algorithm>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <queue>
using namespace std;

#include "palisade.h"
#include "cryptocontext.h"
#include "circuitvalue.h"
#include "circuitnode.h"
#include "palisadecircuit.h"

namespace lbcrypto {

class CircuitNode;

template<typename Element>
class CircuitNodeWithValue;

class CircuitGraph {
	map<usint,CircuitNode*>			allNodes;
	vector<usint>					inputs;
	vector<usint>					outputs;

	bool nodeExists(int id) {
		return allNodes.find(id) != allNodes.end();
	}

	// can add input if the node exists but it's not in the input list yet
	bool canAddInput(usint id) {
		return nodeExists(id) &&
				std::find(inputs.begin(), inputs.end(), id) == inputs.end();
	}

public:
	CircuitGraph() {}
	virtual ~CircuitGraph() {}

	int GenNodeNumber() { return allNodes.rbegin()->first + 1; }

	const map<usint,CircuitNode*>& getAllNodes() const { return allNodes; }

	CircuitNode *getNodeById(usint id) {
		auto it = allNodes.find(id);
		if( it == allNodes.end() ) {
			return 0;
		}
		return it->second;
	}

	bool addNode(CircuitNode *n, int id) {
		if( nodeExists(id) )
			return false;
		allNodes[id] = n;
		return true;
	}

	bool removeNode(int n) {
		if( nodeExists(n) == false )
			return false;
		allNodes.erase(n);
		return true;
	}

	bool addInput(int n) {
		if( canAddInput(n) ) {
			inputs.push_back(n);
			return true;
		}
		return false;
	}

	void addOutput(int n) {
		outputs.push_back(n);
	}

	const vector<usint>& getInputs() const { return inputs; }
	const vector<usint>& getOutputs() const { return outputs; }
};

template<typename Element>
class CircuitGraphWithValues {
	CircuitGraph&								g;
	map<usint,CircuitNodeWithValue<Element>*>	allNodes;

	void processNodeDepth(CircuitNodeWithValue<Element> *n, queue<CircuitNodeWithValue<Element>*>&);

public:
	CircuitGraphWithValues(CircuitGraph& cg) : g(cg) {
		for( map<usint,CircuitNode*>::const_iterator it = cg.getAllNodes().begin(); it != cg.getAllNodes().end(); it++ ) {
			allNodes[ it->first ] = CircuitNodeWithValue<Element>::ValueNodeFactory( it->second );
		}
	}

	virtual ~CircuitGraphWithValues() {
		for( typename map<usint,CircuitNodeWithValue<Element>*>::iterator it = allNodes.begin(); it != allNodes.end(); it++ ) {
			delete ( it->second );
		}
		allNodes.clear();
	}

	int GenNodeNumber() { return allNodes.rbegin()->first + 1; }

	const vector<usint>& getInputs() const { return g.getInputs(); }
	const vector<usint>& getOutputs() const { return g.getOutputs(); }

	map<usint,CircuitNodeWithValue<Element>*>& getAllNodes() { return allNodes; }

	CircuitNodeWithValue<Element> *getNodeById(usint id) {
		auto it = allNodes.find(id);
		if( it == allNodes.end() ) {
			return 0;
		}
		return it->second;
	}

	void Preprocess();
	void GenerateOperationList(CryptoContext<Element> cc);

	void PrintOperationSet(ostream& out, bool verbose=false) {
		map<usint,map<OpType,int>>& opmap = CircuitNodeWithValue<Element>::GetOperationsMap();
		map<OpType,int> ops;

		for( auto& it : opmap ) {
			for( auto& iit : it.second ) {
				ops[iit.first] += iit.second;
			}
		}

		if( verbose ) {
			for( auto& it : opmap ) {
				out << "Node " << it.first << " ";
				for( auto& iit : it.second ) {
					out << iit.first << ":" << iit.second << " ";
				}
				out << endl;
			}
		}
		else {
			for( auto op : ops )
				out << op.first << ":" << op.second << endl;
		}
	}

	void ApplyRuntimeEstimates(map<OpType,double>& stats);

	void processNodeDepth();
	void resetAllDepths();

	int GetMaximumDepth() {
		int answer = -1;

		for( const auto& n : this->getAllNodes() )
			if( n.second->getOutputDepth() > answer )
				answer = n.second->getOutputDepth();
		return answer;
	}

	void Execute(CryptoContext<Element> cc);

	wire_type GetTypeForNode(usint id) {
		auto np = getNodeById(id);
		if( np )
			return np->GetType();
		return UNKNOWN;
	}

	void DisplayGraph(ostream& f) const;

	void ClearVisited() {
		for( auto node : allNodes )
			node.second->ClearVisit();
	}
};

}

#endif /* SRC_CIRCUIT_CIRCUITGRAPH_H_ */
