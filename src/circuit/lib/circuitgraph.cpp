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
CircuitGraphWithValues<Element>::DisplayGraph(ostream& f) const
{
	f << "digraph G {" << endl;

	for( auto it = allNodes.begin(); it != allNodes.end(); it++ ) {
		f << *it->second << endl;
	}
	f << "}" << endl;
}

template<typename Element>
void
CircuitGraphWithValues<Element>::Preprocess()
{
	resetAllDepths();

	for( int output : getOutputs() ) {
		auto out = getNodeById(output);
		out->setOutputDepth(1);
	}

	processNodeDepth();
}

template<typename Element>
void
CircuitGraphWithValues<Element>::GenerateOperationList(CryptoContext<Element> cc)
{
	this->ClearVisited();
	CircuitNodeWithValue<Element>::GetOperationsMap().clear();
	for( int output : getOutputs() ) {
		auto out = getNodeById(output);
		out->Evaluate(GetOperationsList, cc, *this);

		cout << output << endl;
		for( auto x : out->GetOperationsMap()[output] ) {
			cout << x.first << ":" << x.second << endl;
		}
	}
}

template<typename Element>
void
CircuitGraphWithValues<Element>::ApplyRuntimeEstimates(map<OpType,double>& stats)
{
	map<usint,map<OpType,int>>& opsmap = CircuitNodeWithValue<Element>::GetOperationsMap();
	for( auto& node : this->getAllNodes() ) {
		double est = 0;
		for( auto& nodeops : opsmap[node.first] ) {
			est += stats[nodeops.first] * nodeops.second;
		}

		cout << "node " << node.first << " est " << est << endl;
		node.second->SetRuntimeEstimateNode(est);
	}

	this->ClearVisited();
	for( int output : getOutputs() ) {
		CircuitNodeWithValue<Element> *out = getNodeById(output);
		out->Evaluate(CalculateRuntimeEstimates, 0, *this);
	}
}

template<typename Element>
void
CircuitGraphWithValues<Element>::Execute(CryptoContext<Element> cc)
{
	for( int output : getOutputs() ) {
		CircuitNodeWithValue<Element> *out = getNodeById(output);
		out->Evaluate(Evaluate, cc, *this);
	}
}

template<typename Element>
static void
insertMRbetween(CircuitGraphWithValues<Element> *g, CircuitNodeWithValue<Element> *up, CircuitNodeWithValue<Element> *down)
{
	// FIXME - don't add M/R if it isn't supported in the scheme
	return;


	if( down->isModReduce() ) {
		// just expand the thing
		down->setInputDepth(up->getOutputDepth());
		return;
	}

	usint outName = up->GetId();
	usint inName = down->GetId();

	ModReduceNode mrn(g->GenNodeNumber(), vector<usint>({outName}));
	auto newMR = new ModReduceNodeWithValue<Element>(&mrn);
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

	g->getAllNodes()[newMR->GetId()] = newMR;

	return; // g->addNode(newMR, newMR->GetId());
}

template<typename Element>
void
CircuitGraphWithValues<Element>::processNodeDepth(CircuitNodeWithValue<Element> *n, queue<CircuitNodeWithValue<Element> *>& nodeQueue)
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
			insertMRbetween(this, in, n);
		}
		else if( in->getOutputDepth() < inDepth ) {
			in->resetOutputDepth(inDepth);
			nodeQueue.push(in);

			// now find all the links leaving "in" that might need a mod/reduce

			auto outputs = in->getOutputs();

			for( usint otherOut : outputs ) {
				if( otherOut == i )
					continue;

				CircuitNodeWithValue<Element> *out = getNodeById(otherOut);
				if( out == 0 ) {
					throw std::logic_error( "There is no node with id " + to_string(otherOut) + " for node " + to_string(in->GetId()) + " in the graph!!" );
				}

				usint outDepth = out->getInputDepth();

				if( inDepth > outDepth ) {
					insertMRbetween(this, in, out);
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
CircuitGraphWithValues<Element>::resetAllDepths()
{
	for( auto it = allNodes.begin() ; it != allNodes.end() ; it++ )
		it->second->resetDepth();
}


template<typename Element>
void
CircuitGraphWithValues<Element>::processNodeDepth()
{
	queue<CircuitNodeWithValue<Element> *> items;

	for( int i : this->getOutputs() )
		items.push(allNodes[i]);

	while( items.size() > 0 ) {
		processNodeDepth(items.front(), items);
		items.pop();
	}
}

}
