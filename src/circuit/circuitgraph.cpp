/*
 * CircuitGraph.cpp
 *
 *  Created on: Aug 17, 2016
 *      Author: gerardryan
 */

#include "CircuitGraph.h"

CircuitGraph::CircuitGraph(const CircuitGraph& from)
{
	map<string,string> nameMap;
	map<CircuitNode*,CircuitNode*> valueMap;

	// first, clone all of the nodes
	for( map<string,CircuitNode*>::const_iterator it = from.allNodes.begin(); it != from.allNodes.end(); it++ ) {
		CircuitNode *old = it->second;
		string newName = CircuitNode::generateNodeName();
		CircuitNode *clone = old->clone(newName, old->getInputs().size());
		nameMap[old->getName()] = newName;
		valueMap[old] = clone;

		// note we are copying old names and old pointers; will adjust later
		for( int i = 0; i < old->getInputs().size(); i++ )
			clone->setInput(i, old->getInput(i) );
		for( string output : old->getOutputs() )
			clone->addOutput(output);
		clone->setInputDepth( old->getInputDepth() );
		clone->setOutputDepth( old->getOutputDepth() );
		clone->setValue( old->getValue() );

		this->allNodes[newName] = clone;
	}

	// now adjust the "old" pointers and names to the new values
	for( map<string,CircuitNode*>::const_iterator it = this->allNodes.begin(); it != this->allNodes.end(); it++ ) {
		CircuitNode *node = it->second;

		for( int i=0; i<node->getInputs().size(); i++ ) {
			CircuitNode *inputnode = valueMap[ node->getInputs().at(i) ];
			node->setInput(i, inputnode);
		}

		// now the inputs for every node in the new graph are also in the new graph

		// update the node outputs
		set<string> outputs = node->getOutputs();
		for( string o : outputs ) {
			node->delOutput(o);
			node->addOutput(nameMap[o]);
		}
	}

	for( string input : from.inputs )
		this->inputs.push_back( nameMap[input] );

	for( string output : from.outputs ) {
		this->outputs.insert( nameMap[output] );
	}

	MarkAllOutputs();
}

// replace all instances of a name in nameMap with the new value
// replace all instances of a pointer in valueMap with the new value
bool
CircuitGraph::bindParameters(map<string,string>& nameMap, map<CircuitNode *, CircuitNode *>& valueMap)
{
	for( map<string,CircuitNode*>::iterator it = allNodes.begin() ; it != allNodes.end() ; it++ ) {
		CircuitNode *n = it->second;
		set<string> outs(n->getOutputs());
		for( string o : outs ) {
			map<string,string>::iterator it = nameMap.find(o);
			if( it != nameMap.end() ) {
				n->delOutput(it->first);
				n->addOutput(it->second);
			}
		}

		for( int i=0; i<n->getInputs().size(); i++ ) {
			cout << "node " + n->getName() + " has input " + n->getInputs().at(i)->getName() + " in position " << i << endl;
			map<CircuitNode *, CircuitNode *>::iterator it = valueMap.find( n->getInputs().at(i) );
			if( it != valueMap.end() ) {
				CircuitNode *oldN = n->getInput(i);
				n->setInput(i, it->second);
			}
		}
	}

	return true;
}

void
CircuitGraph::DisplayGraph()
{
	std::cout << "digraph G {" << std::endl;
	std::cout << "Inputs -> Outputs;" << std::endl;

	for( map<string,CircuitNode*>::iterator it = allNodes.begin(); it != allNodes.end(); it++ ) {
		std::cout << *it->second << std::endl;
	}
	std::cout << "}" << std::endl;
}

void
CircuitGraph::DisplayAllDepths()
{
	for( map<string,CircuitNode*>::iterator it = allNodes.begin(); it != allNodes.end(); it++ ) {
		std::cout << it->second->getName() << " Depth " << it->second->getInputDepth() << std::endl;
	}
}

void
CircuitGraph::Execute(CircuitSim *cs)
{
	resetAllDepths();
	Value::setPtmod(cs->getPlaintextModulus());

	for( string output : cs->getOutputs() ) {
		CircuitNode *out = getNodeByName(output);
		out->setOutputDepth(1);
		out->processNodeDepth(this);
	}

	for( string output : cs->getOutputs() ) {
		CircuitNode *out = getNodeByName(output);
		std::cout << "Processing " << output << std::endl;
		Value v = out->eval();
		std::cout << v << std::endl;
	}
}

void
CircuitGraph::MarkAllOutputs()
{
	for( string o : outputs ) {
		CircuitNode *n = getNodeByName(o);
		if( n == 0 ) {
			cerr << "no node for output " << o << endl;
		}
		else
			n->setAsOutput();
	}
}

// every node in newG gets added to this
void
CircuitGraph::mergeGraph(CircuitGraph *newG)
{
	const map<string,CircuitNode*>& nodes = newG->getAllNodes();
	for( map<string,CircuitNode*>::const_iterator it = nodes.begin(); it != nodes.end(); it++ ) {
		// note we unmark each one of these nodes as outputs; they are not outputs of the larger graph they're joining
		it->second->unsetAsOutput();
		this->addNode(it->second);
	}
}
