/*
 * CircuitGraph.h
 *
 *  Created on: Aug 17, 2016
 *      Author: gerardryan
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
#include "circuitinput.h"

namespace lbcrypto {
class CircuitNode;

class CircuitGraph {
	map<usint,CircuitNode*>				allNodes;
	vector<usint>						inputs;
	set<usint>							outputs;

	const map<usint,CircuitNode*>& getAllNodes() const { return allNodes; }

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

	int GenNodeNumber() { return allNodes.size() + 1; }

	void processNodeDepth();
	void processNodeDepth(CircuitNode *n, queue<CircuitNode*>&);

	void mergeGraph(CircuitGraph *newG);

	void DisplayGraph() const;
	void DisplayDecryptedGraph(CryptoContext<ILDCRT2n> cc, shared_ptr<LPPrivateKey<ILDCRT2n>> k) const;

	void Prepare();
	void Execute(CryptoContext<ILDCRT2n> cc);

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
		outputs.insert(n);
	}

	const vector<wire_type> GetInputTypes();

	void MarkAllOutputs();

	const usint getInput(usint i) const { return inputs[i]; }
	const vector<usint>& getInputs() const { return inputs; }
	const set<usint>& getOutputs() const { return outputs; }

	void resetAllDepths();

	void SetStreamKey(CryptoContext<ILDCRT2n> cc, shared_ptr<LPPrivateKey<ILDCRT2n>> k) const;
};

}

#endif /* SRC_CIRCUIT_CIRCUITGRAPH_H_ */
