/*
 * CircuitGraph.cpp
 *
 *  Created on: Aug 17, 2016
 *      Author: gerardryan
 */

#include "circuitgraph.h"
#include "circuitnode.h"
#include "palisade.h"
#include "cryptocontext.h"

namespace lbcrypto {

//CircuitGraph::CircuitGraph(const CircuitGraph& from)
//{
//	map<string,string> nameMap;
//	map<CircuitNode*,CircuitNode*> valueMap;
//
//	// first, clone all of the nodes
//	for( map<string,CircuitNode*>::const_iterator it = from.allNodes.begin(); it != from.allNodes.end(); it++ ) {
//		CircuitNode *old = it->second;
//		string newName = CircuitNode::generateNodeName();
//		CircuitNode *clone = old->clone(newName, old->getInputs().size());
//		nameMap[old->getName()] = newName;
//		valueMap[old] = clone;
//
//		// note we are copying old names and old pointers; will adjust later
//		for( int i = 0; i < old->getInputs().size(); i++ )
//			clone->setInput(i, old->getInput(i) );
//		for( string output : old->getOutputs() )
//			clone->addOutput(output);
//		clone->setInputDepth( old->getInputDepth() );
//		clone->setOutputDepth( old->getOutputDepth() );
//		clone->setValue( old->getValue() );
//
//		this->allNodes[newName] = clone;
//	}
//
//	// now adjust the "old" pointers and names to the new values
//	for( map<string,CircuitNode*>::const_iterator it = this->allNodes.begin(); it != this->allNodes.end(); it++ ) {
//		CircuitNode *node = it->second;
//
//		for( int i=0; i<node->getInputs().size(); i++ ) {
//			CircuitNode *inputnode = valueMap[ node->getInputs().at(i) ];
//			node->setInput(i, inputnode);
//		}
//
//		// now the inputs for every node in the new graph are also in the new graph
//
//		// update the node outputs
//		set<string> outputs = node->getOutputs();
//		for( string o : outputs ) {
//			node->delOutput(o);
//			node->addOutput(nameMap[o]);
//		}
//	}
//
//	for( string input : from.inputs )
//		this->inputs.push_back( nameMap[input] );
//
//	for( string output : from.outputs ) {
//		this->outputs.insert( nameMap[output] );
//	}
//
//	MarkAllOutputs();
//}

// replace all instances of a name in nameMap with the new value
// replace all instances of a pointer in valueMap with the new value
bool
CircuitGraph::bindParameters(map<string,string>& nameMap, map<CircuitNode *, CircuitNode *>& valueMap)
{
	for( auto it = allNodes.begin() ; it != allNodes.end() ; it++ ) {
		CircuitNode *n = it->second;
		//auto outs(n->getOutputs());
		//for( auto o : outs ) {
//			map<string,string>::iterator it = nameMap.find(o);
//			if( it != nameMap.end() ) {
//				n->delOutput(it->first);
//				n->addOutput(it->second);
//			}
		//}

		for( size_t i=0; i<n->getInputs().size(); i++ ) {
			cout << "node " << n->GetId() << " has input " << n->getInputs().at(i) << " in position " << i << endl;
//			map<CircuitNode *, CircuitNode *>::iterator it = valueMap.find( n->getInputs().at(i) );
//			if( it != valueMap.end() ) {
//				CircuitNode *oldN = n->getInput(i);
//				n->setInput(i, it->second);
//			}
		}
	}

	return true;
}

void
CircuitGraph::DisplayGraph()
{
	std::cout << "digraph G {" << std::endl;
	std::cout << "Inputs -> Outputs;" << std::endl;

	for( auto it = allNodes.begin(); it != allNodes.end(); it++ ) {
		std::cout << *it->second << std::endl;
	}
	std::cout << "}" << std::endl;
}

void
CircuitGraph::DisplayAllDepths()
{
	for( auto it = allNodes.begin(); it != allNodes.end(); it++ ) {
		std::cout << it->second->GetId() << " Depth " << it->second->getInputDepth() << std::endl;
	}
}

void
CircuitGraph::Execute(CryptoContext<ILVector2n> cc)
{
	std::cout << "resetting depths" << std::endl;
	resetAllDepths();

	for( int output : getOutputs() ) {
		CircuitNode *out = getNodeById(output);
		out->setOutputDepth(1);
	}

	processNodeDepth();

	for( int output : getOutputs() ) {
		CircuitNode *out = getNodeById(output);
		std::cout << "Processing output " << output << std::endl;
		Value v = out->eval(cc, *this);
	}
}

void
CircuitGraph::MarkAllOutputs()
{
	for( auto o : outputs ) {
		allNodes[o]->setAsOutput();
	}
}

const vector<wire_type> CircuitGraph::GetInputTypes() {
	vector<wire_type>	types;

	for( usint i : getInputs() ) {
		types.push_back( allNodes[i]->GetType() );
	}

	return types;
}

// every node in newG gets added to this
void
CircuitGraph::mergeGraph(CircuitGraph *newG)
{
	auto nodes = newG->getAllNodes();
	for( auto it = nodes.begin(); it != nodes.end(); it++ ) {
		// note we unmark each one of these nodes as outputs; they are not outputs of the larger graph they're joining
		it->second->unsetAsOutput();
		this->addNode(it->second, it->second->GetId());
	}
}

static bool
insertMRbetween(CircuitGraph *g, CircuitNode *up, CircuitNode *down)
{
	if( down->isModReduce() ) {
		// just expand the thing
		down->setInputDepth(up->getOutputDepth());
		return true;
	}

	usint outName = up->GetId();
	usint inName = down->GetId();

	CircuitNode *newMR = new ModReduceNode(g->GenNodeNumber(), vector<usint>({outName}));
	newMR->setInputDepth(up->getOutputDepth());
	newMR->setOutputDepth(down->getInputDepth());

	// replace the old input to down (up) with the new input (newMR)
	bool didChange = false;
	for( size_t i = 0; i < down->getInputs().size(); i++ ) {
		if( down->getInputs()[i] == up->GetId() ) {
			down->setInput(i, newMR->GetId());
			didChange = true;
			break;
		}
	}

	if( didChange == false ) {
		throw std::logic_error("something is screwed up; could not find up in down's inputs!");
	}

	// link in the new mod/reduce between up and down
	up->addOutput(newMR->GetId());

	// remove inName from out; remove otherOut from inName
	up->delOutput(inName);

	return g->addNode(newMR, newMR->GetId());
}

void
CircuitGraph::processNodeDepth(CircuitNode *n, queue<CircuitNode *>& nodeQueue)
{
	cout << "processNodeDepth for node " << *n << endl;
	for( int i : n->getInputs() ) cout << "  input:" << i << endl;
	for( int i : n->getOutputs() ) cout << " output:" << i << endl;
	// calculate what the input depth should be for this node given its output depth
	n->setBottomUpDepth();
	usint inDepth = n->getInputDepth();

	// assign new output depth to every node providing input
	for( int i : n->getInputs() ) {
		auto in = getNodeById(i);
		cout << "input is " << *in << endl;

		// if this node has not been seen yet... set its output
		if( in->getOutputDepth() == 0 ) {
			in->setOutputDepth(inDepth);
			nodeQueue.push(in);
		}
		else if( in->getOutputDepth() > inDepth ) {
			if( insertMRbetween(this, in, n) == false ) {
				std::cout << "problem inserting mr" << std::endl;
			}
		}
		else if( in->getOutputDepth() < inDepth ) {
			in->resetOutputDepth(inDepth);
			nodeQueue.push(in);

			// now find all the links leaving "in" that might need a mod/reduce

			auto otherOutputs(in->getOutputs());
			for( usint otherOut : otherOutputs ) {
				CircuitNode *out = getNodeById(otherOut);
				if( out == (CircuitNode *)0 ) {
					std::cout << "There is no node with id " << otherOut << " for node " << in->GetId() << " in the graph!!" << endl;
					continue;
				}
				usint outDepth = out->getInputDepth();

				if( inDepth > outDepth ) {
					if( insertMRbetween(this, in, out) == false ) {
						std::cout << "problem inserting mr" << std::endl;
					}
				} else if( inDepth < outDepth ) {
					std::cout << "Node " << otherOut << " has inputDepth " << outDepth
							<< " and node " << in << " has outputDepth " << inDepth << std::endl;
				}
			}
		}
//		else if( in->getOutputDepth() == inDepth ) { // do nothing; we are already at the proper depth }
	}
}

void
CircuitGraph::resetAllDepths()
{
	for( auto it = allNodes.begin() ; it != allNodes.end() ; it++ )
		it->second->resetDepth();
}


void
CircuitGraph::processNodeDepth()
{
	queue<CircuitNode *> items;

	for( int i : this->getOutputs() )
		items.push(allNodes[i]);

	while( items.size() > 0 ) {
		processNodeDepth(items.front(), items);
		items.pop();
	}
}

}
