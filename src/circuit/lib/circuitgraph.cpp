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

void
CircuitGraph::DisplayGraph() const
{
	cout << "digraph G {" << endl;
	cout << "Inputs -> Outputs;" << endl;
	cout << "{rank=max; Outputs};" << endl;

	for( auto it = allNodes.begin(); it != allNodes.end(); it++ ) {
		cout << *it->second << endl;
	}
	cout << "}" << endl;
}

void
CircuitGraph::SetStreamKey(CryptoContext<ILDCRT2n> cc, shared_ptr<LPPrivateKey<ILDCRT2n>> k) const {
	extern CryptoContext<ILDCRT2n> _graph_cc;
	extern shared_ptr<LPPrivateKey<ILDCRT2n>> _graph_key;

	_graph_cc = cc;
	_graph_key = k;
}


void
CircuitGraph::DisplayDecryptedGraph(CryptoContext<ILDCRT2n> cc, shared_ptr<LPPrivateKey<ILDCRT2n>> k) const
{
	SetStreamKey(cc, k);
	cout << "digraph G {" << endl;
	cout << "Inputs -> Outputs;" << endl;
	cout << "{rank=max; Outputs};" << endl;

	for( auto it = allNodes.begin(); it != allNodes.end(); it++ ) {
		cout << *it->second << endl;
	}
	cout << "}" << endl;
}

void
CircuitGraph::Prepare()
{
	cout << "resetting depths" << endl;
	resetAllDepths();

	for( int output : getOutputs() ) {
		CircuitNode *out = getNodeById(output);
		cout << "setting node " << output << " to 1" << endl;
		out->setOutputDepth(1);
	}

	processNodeDepth();
}

void
CircuitGraph::Execute(CryptoContext<ILDCRT2n> cc)
{
	for( int output : getOutputs() ) {
		CircuitNode *out = getNodeById(output);
		cout << "Evaluating output " << output << endl;
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
	// calculate what the input depth should be for this node given its output depth
	n->setBottomUpDepth();
	usint inDepth = n->getInputDepth();

	// assign new output depth to every node providing input
	for( int i : n->getInputs() ) {
		auto in = getNodeById(i);

		// if this node has not been seen yet... set its output
		if( in->getOutputDepth() == 0 ) {
			in->setOutputDepth(inDepth);
			nodeQueue.push(in);
		}
		else if( in->getOutputDepth() > inDepth ) {
			if( insertMRbetween(this, in, n) == false ) {
				throw std::logic_error("problem inserting mr");
			}
		}
		else if( in->getOutputDepth() < inDepth ) {
			in->resetOutputDepth(inDepth);
			nodeQueue.push(in);

			// now find all the links leaving "in" that might need a mod/reduce

			auto outputs = in->getOutputs();

			for( usint otherOut : outputs ) {
				if( otherOut == i )
					continue;

				CircuitNode *out = getNodeById(otherOut);
				if( out == (CircuitNode *)0 ) {
					throw std::logic_error( "There is no node with id " + to_string(otherOut) + " for node " + to_string(in->GetId()) + " in the graph!!" );
				}

				usint outDepth = out->getInputDepth();

				if( inDepth > outDepth ) {
					if( insertMRbetween(this, in, out) == false ) {
						throw std::logic_error("problem inserting mr");
					}
				} else if( inDepth < outDepth ) {
					cout << "Node " << otherOut << " has inputDepth " << outDepth
							<< " and node " << in << " has outputDepth " << inDepth << endl;
				}
			}
		}
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
