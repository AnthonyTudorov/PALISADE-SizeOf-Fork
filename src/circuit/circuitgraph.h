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

class CircuitGraph {
	map<string,CircuitNode*>	allNodes;
	vector<string>				inputs;
	set<string>					outputs;

	const map<string,CircuitNode*>& getAllNodes() const { return allNodes; }

	bool nodeExists(string name) {
		return allNodes.find(name) != allNodes.end();
	}

	// can add input if the node exists but it's not in the input list yet
	bool canAddInput(string name) {
		return allNodes.find(name) != allNodes.end() &&
				std::find(inputs.begin(), inputs.end(), name) == inputs.end();
	}

public:
	CircuitGraph() {}
	virtual ~CircuitGraph() {}

	CircuitGraph(const CircuitGraph& from);

	void mergeGraph(CircuitGraph *newG);

	void DisplayGraph();
	void DisplayAllDepths();
	void Execute(CircuitSim *);

	CircuitNode *getNodeByName(string name) {
		map<string,CircuitNode*>::iterator it = allNodes.find(name);
		if( it == allNodes.end() ) {
			return 0;
		}
		return it->second;
	}

	void rename(CircuitNode *n, string newName) {
		string oldName = n->getName();

		// make every one of my inputs have newName as an output, not oldname
		for( CircuitNode *in : n->getInputs() ) {
			in->renameOutput(oldName, newName);
		}

		allNodes.erase( oldName );
		n->setName(newName);
		allNodes[newName] = n;

		for( int i=0; i<inputs.size(); i++ )
			if( inputs[i] == oldName )
				inputs[i] = newName;

		if( outputs.find(oldName) != outputs.end() ) {
			outputs.erase(oldName);
			outputs.insert(newName);
		}
	}

	bool addNode(CircuitNode *n) {
		if( nodeExists(n->getName()) )
			return false;
		allNodes[n->getName()] = n;
		return true;
	}

	bool removeNode(CircuitNode *n) {
		if( nodeExists(n->getName()) == false )
			return false;
		allNodes.erase(n->getName());
		return true;
	}

	bool addInput(string name) {
		if( canAddInput(name) ) {
			inputs.push_back(name);
			return true;
		}
		return false;
	}

	void addOutput(string name) { outputs.insert(name); }
	void MarkAllOutputs();

	const string getInput(int i) const { return inputs[i]; }
	const vector<string>& getInputs() const { return inputs; }
	const set<string>& getOutputs() const { return outputs; }

	void resetAllDepths() {
		for( map<string,CircuitNode*>::iterator it = allNodes.begin() ; it != allNodes.end() ; it++ )
			it->second->resetDepth();
	}

	bool bindParameters(map<string,string>& nameMap, map<CircuitNode *, CircuitNode *>& valueMap);

};

#endif /* SRC_CIRCUIT_CIRCUITGRAPH_H_ */
