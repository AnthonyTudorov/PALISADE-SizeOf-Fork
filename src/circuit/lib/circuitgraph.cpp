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

template<typename Element>
void
CircuitGraph<Element>::DisplayGraph() const
{
	cout << "digraph G {" << endl;
	cout << "Inputs -> Outputs;" << endl;
	cout << "{rank=max; Outputs};" << endl;

	for( auto it = allNodes.begin(); it != allNodes.end(); it++ ) {
		cout << *it->second << endl;
	}
	cout << "}" << endl;
}

template<typename Element>
void
CircuitGraph<Element>::SetStreamKey(CryptoContext<Element> cc, shared_ptr<LPPrivateKey<Element>> k) const {
	extern CryptoContext<Element> _graph_cc;
	extern shared_ptr<LPPrivateKey<Element>> _graph_key;

	_graph_cc = cc;
	_graph_key = k;
}


template<typename Element>
void
CircuitGraph<Element>::DisplayDecryptedGraph(CryptoContext<Element> cc, shared_ptr<LPPrivateKey<Element>> k) const
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

template<typename Element>
void
CircuitGraph<Element>::Prepare()
{
	cout << "resetting depths" << endl;
	resetAllDepths();

	for( int output : getOutputs() ) {
		CircuitNode<Element> *out = getNodeById(output);
		cout << "setting node " << output << " to 1" << endl;
		out->setOutputDepth(1);
	}

	processNodeDepth();
}

template<typename Element>
void
CircuitGraph<Element>::Execute(CryptoContext<Element> cc)
{
	for( int output : getOutputs() ) {
		CircuitNode<Element> *out = getNodeById(output);
		cout << "Evaluating output " << output << endl;
		out->eval(cc, *this);
	}
}

template<typename Element>
const vector<wire_type> CircuitGraph<Element>::GetInputTypes() {
	vector<wire_type>	types;

	for( usint i : getInputs() ) {
		types.push_back( allNodes[i]->GetType() );
	}

	return types;
}

template<typename Element>
static bool
insertMRbetween(CircuitGraph<Element> *g, CircuitNode<Element> *up, CircuitNode<Element> *down)
{
	if( down->isModReduce() ) {
		// just expand the thing
		down->setInputDepth(up->getOutputDepth());
		return true;
	}

	usint outName = up->GetId();
	usint inName = down->GetId();

	CircuitNode<Element> *newMR = new ModReduceNode<Element>(g->GenNodeNumber(), vector<usint>({outName}));
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

template<typename Element>
void
CircuitGraph<Element>::processNodeDepth(CircuitNode<Element> *n, queue<CircuitNode<Element> *>& nodeQueue)
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

				CircuitNode<Element> *out = getNodeById(otherOut);
				if( out == (CircuitNode<Element> *)0 ) {
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

template<typename Element>
void
CircuitGraph<Element>::resetAllDepths()
{
	for( auto it = allNodes.begin() ; it != allNodes.end() ; it++ )
		it->second->resetDepth();
}


template<typename Element>
void
CircuitGraph<Element>::processNodeDepth()
{
	queue<CircuitNode<Element> *> items;

	for( int i : this->getOutputs() )
		items.push(allNodes[i]);

	while( items.size() > 0 ) {
		processNodeDepth(items.front(), items);
		items.pop();
	}
}

}
