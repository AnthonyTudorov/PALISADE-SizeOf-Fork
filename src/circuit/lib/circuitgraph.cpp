/**
 * @file circuitgraph.cpp -- Representation of a circuit as a graph of circuit nodes.
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

#include "circuitgraph.h"
#include "circuitnode.h"
#include "palisade.h"
#include "cryptocontext.h"

namespace lbcrypto {

void
CircuitGraph::DisplayGraph(ostream* out) const
{
	*out << "digraph G {" << endl;

	for( auto it = allNodes.begin(); it != allNodes.end(); it++ ) {
		*out << *it->second << endl;
	}
	*out << "}" << endl;
}

template<typename Element>
void
CircuitGraphWithValues<Element>::SetStreamKey(CryptoContext<Element> cc, shared_ptr<LPPrivateKey<Element>> k) const {
	CircuitGraphWithValues<Element>::_graph_cc = cc;
	CircuitGraphWithValues<Element>::_graph_key = k;
}

template<typename Element>
void
CircuitGraphWithValues<Element>::DisplayGraph(ostream* f) const
{
	this->g.DisplayGraph(f);
}

template<typename Element>
void
CircuitGraphWithValues<Element>::DisplayDecryptedGraph(ostream* f, CryptoContext<Element> cc, shared_ptr<LPPrivateKey<Element>> k) const
{
	SetStreamKey(cc, k);
	*f << "digraph G {" << endl;

	for( auto it = allNodes.begin(); it != allNodes.end(); it++ ) {
		*f << *it->second << endl;
	}
	*f << "}" << endl;
}

void
CircuitGraph::Preprocess()
{
	resetAllDepths();

	for( int output : getOutputs() ) {
		CircuitNode *out = getNodeById(output);
		out->setOutputDepth(1);
	}

	processNodeDepth();
}

void
CircuitGraph::GenerateOperationList(vector<CircuitSimulation>& ops)
{
	for( int output : getOutputs() ) {
		CircuitNode *out = getNodeById(output);
		ClearVisited();
		out->simeval(*this, ops);
	}
}

void
CircuitGraph::UpdateRuntimeEstimates(vector<CircuitSimulation>& steps, map<OpType,TimingStatistics>& stats)
{
	// first make sure we have estimates for every operation performed
	set<OpType> ops;
	for( auto &s : steps ) {
		ops.insert( s.op );
	}

	for( OpType o : ops ) {
		if( stats.find(o) == stats.end() ) {
			cout << "WARNING there are no measurements for " << o << endl;
		}
	}

	// mark each of the nodes with a time estimate
	for( size_t i=0; i<steps.size(); i++ ) {
		CircuitNode *node = getNodeById(steps[i].nodeId);
		auto this_est = stats[ steps[i].op ];
		node->SetRuntime(&this_est);
	}
}

void
CircuitGraph::PrintRuntimeEstimates(ostream& out)
{
	for( int output : getOutputs() ) {
		CircuitNode *o = getNodeById(output);
		ClearVisited();
		o->CircuitVisit(*this);
		out << "RUNTIME ESTIMATE FOR Output " << output << " " << GetRuntime() << endl;
	}
}

template<typename Element>
void
CircuitGraphWithValues<Element>::Execute(CryptoContext<Element> cc)
{
	for( int output : getOutputs() ) {
		CircuitNodeWithValue<Element> *out = getNodeById(output);
		out->eval(cc, *this);
	}
}

template<typename Element>
const vector<wire_type> CircuitGraphWithValues<Element>::GetInputTypes() {
	vector<wire_type>	types;

	for( usint i : getInputs() ) {
		types.push_back( allNodes[i]->GetType() );
	}

	return types;
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
	for( usint i : n->getInputs() ) {
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
