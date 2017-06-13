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

#include "circuitgraph.h"
#include "circuitnode.h"

namespace lbcrypto {

template<typename Element>
CryptoContext<Element> CircuitGraphWithValues<Element>::_graph_cc;

template<typename Element>
shared_ptr<LPPrivateKey<Element>> CircuitGraphWithValues<Element>::_graph_key;

ostream& operator<<(ostream& out, const CircuitNode& n)
{
	out << n.GetId() << "  [label=\"" << n.GetId() << "\\n";
	if( n.getInputDepth() != 0 )
		out << "(d=" + std::to_string(n.getInputDepth()) + ")\\n";
	out << n.getNodeLabel();

	out << "\"]; ";

	const vector<usint>& nodeInputs = n.getInputs();
	for( usint input : nodeInputs )
		out << input << " -> " << n.GetId() << "; ";
	if( n.is_output ) {
		out << "{ rank=same; Outputs " << n.GetId() << " }; ";
	}
	if( n.is_input ) {
		out << "{ rank=same; Inputs " << n.GetId() << " }; ";
	}

	return out;
}

template<typename Element>
ostream& operator<<(ostream& out, const CircuitNodeWithValue<Element>& n)
{
	out << n.GetId() << "  [label=\"" << n.GetId() << "\\n";
	if( n.getNode()->getInputDepth() != 0 )
		out << "(d=" + std::to_string(n.getNode()->getInputDepth()) + ")\\n";
	out << n.getNodeLabel();

	const Value<Element>& val = n.getValue();
	if( CircuitGraphWithValues<Element>::_graph_key && val.GetType() != UNKNOWN ) {
		IntPlaintextEncoding pt;
		CircuitGraphWithValues<Element>::_graph_cc.Decrypt(CircuitGraphWithValues<Element>::_graph_key, {val.GetIntVecValue()}, &pt);
		out << "\\n\\[" << pt << "\\] ";
	}

	out << "\"]; ";

	const vector<usint>& nodeInputs = n.getNode()->getInputs();
	for( usint input : nodeInputs )
		out << input << " -> " << n.GetId() << "; ";
	if( n.getNode()->IsOutput() ) {
		out << "{ rank=same; Outputs " << n.GetId() << " }; ";
	}
	if( n.getNode()->IsInput() ) {
		out << "{ rank=same; Inputs " << n.GetId() << " }; ";
	}

	return out;
}



// note that for our purposes here, INT and VECTOR_INT can be considered the same thing
// since an INT is simply a vector with one entry and the rest zeroes

template<typename Element>
Value<Element> EvalAddNodeWithValue<Element>::eval(CryptoContext<Element>& cc, CircuitGraphWithValues<Element>& cg) {
	if( this->value.GetType() != UNKNOWN )
		return this->value;

	if( this->getNode()->getInputs().size() !=2 ) throw std::logic_error("Add requires 2 inputs");

	for( auto z : this->getNode()->getInputs() ) { cout << z << "!!!" << endl; cout << cg.getNodeById(z) << endl; }
	Value<Element> v0( cg.getNodeById(this->getNode()->getInputs()[0])->eval(cc,cg) );
	Value<Element> v1( cg.getNodeById(this->getNode()->getInputs()[1])->eval(cc,cg) );
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
Value<Element> EvalSubNodeWithValue<Element>::eval(CryptoContext<Element>& cc, CircuitGraphWithValues<Element>& cg) {
	if( this->value.GetType() != UNKNOWN )
		return this->value;

	if( this->getNode()->getInputs().size() !=2 ) throw std::logic_error("Subtract requires 2 inputs");

	Value<Element> v0( cg.getNodeById(this->getNode()->getInputs()[0])->eval(cc,cg) );
	Value<Element> v1( cg.getNodeById(this->getNode()->getInputs()[1])->eval(cc,cg) );
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
Value<Element> EvalMultNodeWithValue<Element>::eval(CryptoContext<Element>& cc, CircuitGraphWithValues<Element>& cg) {
	if( this->value.GetType() != UNKNOWN )
		return this->value;

	if( this->getNode()->getInputs().size() !=2 ) throw std::logic_error("Mult requires 2 inputs");

	Value<Element> v0( cg.getNodeById(this->getNode()->getInputs()[0])->eval(cc,cg) );
	Value<Element> v1( cg.getNodeById(this->getNode()->getInputs()[1])->eval(cc,cg) );
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
Value<Element> ModReduceNodeWithValue<Element>::eval(CryptoContext<Element>& cc, CircuitGraphWithValues<Element>& cg) {
	if( this->value.GetType() != UNKNOWN )
		return this->value;

	if( this->getNode()->getInputs().size() != 1 ) throw std::logic_error("ModReduce must have one input");

	Value<Element> v0( cg.getNodeById(this->getNode()->getInputs()[0])->eval(cc,cg) );
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

#define TESTANDMAKE(T,TV,n) { T* node = dynamic_cast<T*>(n); if( node != 0 ) return new TV(node); }

template<typename Element>
CircuitNodeWithValue<Element> *ValueNodeFactory( CircuitNode *n ) {
	TESTANDMAKE( ConstInput, ConstInputWithValue<Element>, n );
	TESTANDMAKE( Input, InputWithValue<Element>, n );
	TESTANDMAKE( Output, OutputWithValue<Element>, n );
	TESTANDMAKE( ModReduceNode, ModReduceNodeWithValue<Element>, n );
	TESTANDMAKE( EvalNegNode, EvalNegNodeWithValue<Element>, n );
	TESTANDMAKE( EvalAddNode, EvalAddNodeWithValue<Element>, n );
	TESTANDMAKE( EvalSubNode, EvalSubNodeWithValue<Element>, n );
	TESTANDMAKE( EvalMultNode, EvalMultNodeWithValue<Element>, n );
	throw std::logic_error("Type not supported in ValueNodeFactory");
}


}
