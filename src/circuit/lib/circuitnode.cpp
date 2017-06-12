/**
 * @file circuitnode.cpp -- Representation of a node in the graph of a circuit
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
 * This code provides support for representing a node in a circuit
 *
 */

#include "circuitnode.h"
#include "circuitgraph.h"

namespace lbcrypto {

template<typename Element>
int	CircuitNode<Element>::step;

template<typename Element>
vector<CircuitSimulation>CircuitNode<Element>::sim;

template<typename Element>
CryptoContext<Element> CircuitGraph<Element>::_graph_cc;

template<typename Element>
shared_ptr<LPPrivateKey<Element>> CircuitGraph<Element>::_graph_key;

template<typename Element>
ostream& operator<<(ostream& out, const CircuitNode<Element>& n)
{
	out << n.nodeId << "  [label=\"" << n.GetId() << "\\n";
	if( n.nodeInputDepth != 0 )
		out << "(d=" + std::to_string(n.nodeInputDepth) + ")\\n";
	out << n.getNodeLabel();

	const Value<Element>& val = n.getValue();
	if( CircuitGraph<Element>::_graph_key && val.GetType() != UNKNOWN ) {
		IntPlaintextEncoding pt;
		CircuitGraph<Element>::_graph_cc.Decrypt(CircuitGraph<Element>::_graph_key, {val.GetIntVecValue()}, &pt);
		out << "\\n\\[" << pt << "\\] ";
	}

	out << "\"]; ";

	const vector<usint>& nodeInputs = n.getInputs();
	for( usint input : nodeInputs )
		out << input << " -> " << n.nodeId << "; ";
	if( n.is_output ) {
		out << "{ rank=same; Outputs " << n.nodeId << " }; ";
	}
	if( n.is_input ) {
		out << "{ rank=same; Inputs " << n.nodeId << " }; ";
	}

	return out;
}


// note that for our purposes here, INT and VECTOR_INT can be considered the same thing
// since an INT is simply a vector with one entry and the rest zeroes

template<typename Element>
Value<Element> EvalAddNode<Element>::eval(CryptoContext<Element>& cc, CircuitGraph<Element>& cg) {
	if( this->value.GetType() != UNKNOWN )
		return this->value;

	if( this->inputs.size() !=2 ) throw std::logic_error("Add requires 2 inputs");

	Value<Element> v0( cg.getNodeById(this->inputs[0])->eval(cc,cg) );
	Value<Element> v1( cg.getNodeById(this->inputs[1])->eval(cc,cg) );
	auto t0 = v0.GetType();
	auto t1 = v1.GetType();

	if( t0 != t1 ) {
		throw std::logic_error("type mismatch for EvalAdd");
	}

	if( t0 == VECTOR_INT ) {
		this->value = cc.EvalAdd(v0.GetIntVecValue(), v1.GetIntVecValue());
		cout << t1 << endl;
	}
	else {
		throw std::logic_error("eval add for types " + std::to_string(t0) + " and " + std::to_string(t1) + " not implemented");
	}

	this->Log();
	return this->value;
}

template<typename Element>
Value<Element> EvalSubNode<Element>::eval(CryptoContext<Element>& cc, CircuitGraph<Element>& cg) {
	if( this->value.GetType() != UNKNOWN )
		return this->value;

	if( this->inputs.size() !=2 ) throw std::logic_error("Subtract requires 2 inputs");

	Value<Element> v0( cg.getNodeById(this->inputs[0])->eval(cc,cg) );
	Value<Element> v1( cg.getNodeById(this->inputs[1])->eval(cc,cg) );
	auto t0 = v0.GetType();
	auto t1 = v1.GetType();

	if( t0 != t1 ) {
		throw std::logic_error("type mismatch for EvalSub");
	}

	if( t0 == VECTOR_INT ) {
		this->value = cc.EvalSub(v0.GetIntVecValue(), v1.GetIntVecValue());
	}
	else {
		throw std::logic_error("eval sub for types " + std::to_string(t0) + " and " + std::to_string(t1) + " are not implemented");
	}

	this->Log();
	return this->value;
}

template<typename Element>
Value<Element> EvalMultNode<Element>::eval(CryptoContext<Element>& cc, CircuitGraph<Element>& cg) {
	if( this->value.GetType() != UNKNOWN )
		return this->value;

	if( this->inputs.size() !=2 ) throw std::logic_error("Mult requires 2 inputs");

	Value<Element> v0( cg.getNodeById(this->inputs[0])->eval(cc,cg) );
	Value<Element> v1( cg.getNodeById(this->inputs[1])->eval(cc,cg) );
	auto t0 = v0.GetType();
	auto t1 = v1.GetType();

	if( t0 != t1 ) {
		throw std::logic_error("type mismatch for EvalSub");
	}

	if( t1 == VECTOR_INT ) {
		this->value = cc.EvalMult(v0.GetIntVecValue(), v1.GetIntVecValue());
	}
	else {
		throw std::logic_error("eval mult for types " + std::to_string(t0) + " and " + std::to_string(t1) + " are not implemented");
	}

	this->Log();
	return this->value;
}

template<typename Element>
Value<Element> ModReduceNode<Element>::eval(CryptoContext<Element>& cc, CircuitGraph<Element>& cg) {
	if( this->value.GetType() != UNKNOWN )
		return this->value;

	if( this->inputs.size() != 1 ) throw std::logic_error("ModReduce must have one input");

	Value<Element> v0( cg.getNodeById(this->inputs[0])->eval(cc,cg) );
	auto t0 = v0.GetType();

	if( t0 == VECTOR_INT ) {
		this->value = cc.ModReduce(v0.GetIntVecValue());
	}
	else {
		throw std::logic_error("modreduce for type " + std::to_string(t0) + " is not implemented");
	}

	this->Log();
	return this->value;
}


}
