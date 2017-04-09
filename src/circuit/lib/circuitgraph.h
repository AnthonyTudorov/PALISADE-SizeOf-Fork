/*
 * CircuitGraph.h
 *
 *  Created on: Aug 17, 2016
 *      Author: gerardryan
 */

#ifndef SRC_CIRCUIT_CIRCUITGRAPH_H_
#define SRC_CIRCUIT_CIRCUITGRAPH_H_

#include "CircuitNode.h"
#include <string>
#include <vector>
#include <map>
#include <set>
using namespace std;

class CircuitSim;

class CircuitGraph {
	map<int,CircuitNode*>	allNodes;
	vector<int>				inputs;
	set<int>				outputs;

	const map<int,CircuitNode*>& getAllNodes() const { return allNodes; }

	bool nodeExists(int id) {
		return allNodes.find(id) != allNodes.end();
	}

	// can add input if the node exists but it's not in the input list yet
	bool canAddInput(int id) {
		return allNodes.find(id) != allNodes.end() &&
				std::find(inputs.begin(), inputs.end(), id) == inputs.end();
	}

public:
	CircuitGraph() {}
	virtual ~CircuitGraph() {}

	int GenNodeNumber() { return allNodes.size() + 1; }

	void processNodeDepth();
	void processNodeDepth(CircuitNode *n, queue<CircuitNode*>&);

	void mergeGraph(CircuitGraph *newG);

	void DisplayGraph();
	void DisplayAllDepths();
	void Execute(CircuitSim *);

	CircuitNode *getNodeById(int id) {
		map<int,CircuitNode*>::iterator it = allNodes.find(id);
		if( it == allNodes.end() ) {
			return 0;
		}
		return it->second;
	}

	bool addNode(CircuitNode *n) {
		if( nodeExists(n->GetId()) )
			return false;
		allNodes[n->GetId()] = n;
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

	void MarkAllOutputs();

	const int getInput(int i) const { return inputs[i]; }
	const vector<int>& getInputs() const { return inputs; }
	const set<int>& getOutputs() const { return outputs; }

	void resetAllDepths() {
		for( auto it = allNodes.begin() ; it != allNodes.end() ; it++ )
			it->second->resetDepth();
	}

	bool bindParameters(map<string,string>& nameMap, map<CircuitNode *, CircuitNode *>& valueMap);

};

#endif /* SRC_CIRCUIT_CIRCUITGRAPH_H_ */
