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

vector<CircuitSimulation> CircuitNode::sim;

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
	if( n.IsOutput() ) {
		out << "(output)\\n";
	}

	out << "\"]; ";

	const vector<usint>& nodeInputs = n.getInputs();
	for( usint input : nodeInputs )
		out << input << " -> " << n.GetId() << "; ";

	return out;
}

template<typename Element>
ostream& operator<<(ostream& out, const CircuitNodeWithValue<Element>& n)
{
	out << n.GetId() << "  [label=\"" << n.GetId() << "\\n";
	if( n.getNode()->getInputDepth() != 0 )
		out << "(d=" + std::to_string(n.getNode()->getInputDepth()) + ")\\n";
	out << n.getNodeLabel();
	if( n.IsOutput() ) {
		out << "(output)\\n";
	}

	out << "\\n(noise=" << n.GetNoise() << ")\\n";

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

	return out;
}

// note that for our purposes here, INT and VECTOR_INT can be considered the same thing
// since an INT is simply a vector with one entry and the rest zeroes

void EvalAddNode::simeval(CircuitGraph& g) {
	if( noiseval != 0 )
		return; // visit only once!

	if( getInputs().size() < 2 ) throw std::logic_error("Add requires at least 2 inputs");

	auto n0 = g.getNodeById(getInputs()[0]);
	n0->simeval(g);
	usint noise = n0->GetNoise();

	for( size_t i=1; i < getInputs().size(); i++ ) {
		auto n1 = g.getNodeById(getInputs()[i]);
		n1->simeval(g);

		noise += n1->GetNoise();
	}

	CircuitNode::PrintLog(cout);
	CircuitNode::Log(GetId(),OpEvalAdd);
	CircuitNode::PrintLog(cout);
	this->SetNoise( noise );
	return;
}

template<typename Element>
Value<Element> EvalAddNodeWithValue<Element>::eval(CryptoContext<Element>& cc, CircuitGraphWithValues<Element>& cg) {
	if( this->value.GetType() != UNKNOWN )
		return this->value;

	if( this->getNode()->getInputs().size() < 2 ) throw std::logic_error("Add requires at least 2 inputs");

	auto n0 = cg.getNodeById(this->getNode()->getInputs()[0]);
	Value<Element> v0( n0->eval(cc,cg) );
	auto t0 = v0.GetType();
	usint noise = n0->GetNoise();

	for( size_t i=1; i < this->getNode()->getInputs().size(); i++ ) {
		auto n1 = cg.getNodeById(this->getNode()->getInputs()[i]);
		Value<Element> v1( n1->eval(cc,cg) );
		auto t1 = v1.GetType();

		if( t0 != t1 ) {
			throw std::logic_error("type mismatch for EvalAdd");
		}

		if( t0 == VECTOR_INT ) {
			v0 = cc.EvalAdd(v0.GetIntVecValue(), v1.GetIntVecValue());
		}
		else if( t0 == MATRIX_INT ) {
			v0 = cc.EvalAddMatrix(v0.GetIntMatValue(), v1.GetIntMatValue());
		}
		else {
			throw std::logic_error("eval add for types " + std::to_string(t0) + " and " + std::to_string(t1) + " not implemented");
		}
		noise += n1->GetNoise();
	}

	this->Log();
	this->SetNoise( noise );
	return this->value = v0;
}

void EvalSubNode::simeval(CircuitGraph& g) {
	if( noiseval != 0 )
		return; // visit only once!

	if( getInputs().size() == 1 ) {
		auto n0 = g.getNodeById(getInputs()[0]);
		n0->simeval(g);
		this->SetNoise( n0->GetNoise() );
		CircuitNode::PrintLog(cout);
		CircuitNode::Log(GetId(),OpEvalNeg);
		CircuitNode::PrintLog(cout);
		return;
	}

	if( getInputs().size() < 2 ) throw std::logic_error("Sub requires at least 2 inputs");

	auto n0 = g.getNodeById(getInputs()[0]);
	n0->simeval(g);
	usint noise = n0->GetNoise();

	for( size_t i=1; i < getInputs().size(); i++ ) {
		auto n1 = g.getNodeById(getInputs()[i]);
		n1->simeval(g);

		noise += n1->GetNoise();
	}

	CircuitNode::PrintLog(cout);
	CircuitNode::Log(GetId(),OpEvalSub);
	CircuitNode::PrintLog(cout);
	this->SetNoise( noise );
	return;
}

template<typename Element>
Value<Element> EvalSubNodeWithValue<Element>::eval(CryptoContext<Element>& cc, CircuitGraphWithValues<Element>& cg) {
	if( this->value.GetType() != UNKNOWN )
		return this->value;

	if( this->getNode()->getInputs().size() == 1 ) {
		// EvalNegate
		auto n0 = cg.getNodeById(this->getNode()->getInputs()[0]);
		Value<Element> v0( n0->eval(cc,cg) );
		auto t0 = v0.GetType();

		if( t0 == VECTOR_INT ) {
			this->value = cc.EvalNegate(v0.GetIntVecValue());
			this->SetNoise( n0->GetNoise() );
			this->Log();
			return this->value;
		}
		else if( t0 == MATRIX_INT ) {
			this->value = cc.EvalNegateMatrix(v0.GetIntMatValue());
			this->SetNoise( n0->GetNoise() );
			this->Log();
			return this->value;
		}
		else {
			throw std::logic_error("eval negate for type " + std::to_string(t0) + " is not implemented");
		}
	}

	if( this->getNode()->getInputs().size() < 2 ) throw std::logic_error("Subtract requires at least 2 inputs");

	auto n0 = cg.getNodeById(this->getNode()->getInputs()[0]);
	Value<Element> v0( n0->eval(cc,cg) );
	auto t0 = v0.GetType();
	usint noise = n0->GetNoise();

	for( size_t i=1; i < this->getNode()->getInputs().size(); i++ ) {
		auto n1 = cg.getNodeById(this->getNode()->getInputs()[i]);
		Value<Element> v1( n1->eval(cc,cg) );
		auto t1 = v1.GetType();

		if( t0 != t1 ) {
			throw std::logic_error("type mismatch for EvalSub");
		}

		if( t0 == VECTOR_INT ) {
			v0 = cc.EvalSub(v0.GetIntVecValue(), v1.GetIntVecValue());
		}
		else if( t0 == MATRIX_INT ) {
			v0 = cc.EvalSubMatrix(v0.GetIntMatValue(), v1.GetIntMatValue());
		}
		else {
			throw std::logic_error("eval sub for types " + std::to_string(t0) + " and " + std::to_string(t1) + " are not implemented");
		}

		noise += n1->GetNoise();
	}

	this->Log();
	this->SetNoise( noise );
	return this->value;
}

void EvalNegNode::simeval(CircuitGraph& g) {
	if( noiseval != 0 )
		return; // visit only once!

	if( getInputs().size() != 1 ) throw std::logic_error("Neg requires 1 input");

	auto n0 = g.getNodeById(getInputs()[0]);
	n0->simeval(g);

	CircuitNode::Log(GetId(),OpEvalNeg);
	this->SetNoise( n0->GetNoise() );
	return;
}

template<typename Element>
Value<Element> EvalNegNodeWithValue<Element>::eval(CryptoContext<Element>& cc, CircuitGraphWithValues<Element>& cg) {
	if( this->value.GetType() != UNKNOWN )
		return this->value;

	if( this->getNode()->getInputs().size() != 1 ) throw std::logic_error("Neg requires 1 input");

	auto n0 = cg.getNodeById(this->getNode()->getInputs()[0]);
	Value<Element> v0( n0->eval(cc,cg) );
	auto t0 = v0.GetType();

	if( t0 == VECTOR_INT ) {
		this->value = cc.EvalNegate(v0.GetIntVecValue());
	}
	else if( t0 == MATRIX_INT ) {
		v0 = cc.EvalNegateMatrix(v0.GetIntMatValue());
	}
	else {
		throw std::logic_error("eval negate for type " + std::to_string(t0) + " is not implemented");
	}

	this->Log();
	this->SetNoise( n0->GetNoise() );
	return this->value;
}

void EvalMultNode::simeval(CircuitGraph& g) {
	if( noiseval != 0 )
		return; // visit only once!

	if( getInputs().size() != 2 ) throw std::logic_error("Mult requires 2 inputs");

	auto n0 = g.getNodeById(getInputs()[0]);
	auto n1 = g.getNodeById(getInputs()[1]);
	n0->simeval(g);
	n1->simeval(g);

	CircuitNode::PrintLog(cout);
	CircuitNode::Log(GetId(),OpEvalMult);
	CircuitNode::PrintLog(cout);
	this->SetNoise( n0->GetNoise() + n1->GetNoise() );
	return;
}

template<typename Element>
Value<Element> EvalMultNodeWithValue<Element>::eval(CryptoContext<Element>& cc, CircuitGraphWithValues<Element>& cg) {
	if( this->value.GetType() != UNKNOWN )
		return this->value;

	if( this->getNode()->getInputs().size() != 2 ) throw std::logic_error("Mult requires 2 inputs");

	auto n0 = cg.getNodeById(this->getNode()->getInputs()[0]);
	auto n1 = cg.getNodeById(this->getNode()->getInputs()[1]);
	Value<Element> v0( n0->eval(cc,cg) );
	Value<Element> v1( n1->eval(cc,cg) );
	auto t0 = v0.GetType();
	auto t1 = v1.GetType();

	if( t0 != t1 ) {
		throw std::logic_error("type mismatch for EvalSub");
	}

	if( t1 == VECTOR_INT ) {
		this->value = cc.EvalMult(v0.GetIntVecValue(), v1.GetIntVecValue());
	}
	else if( t0 == MATRIX_INT ) {
		this->value = cc.EvalMultMatrix(v0.GetIntMatValue(), v1.GetIntMatValue());
	}
	else {
		throw std::logic_error("eval mult for types " + std::to_string(t0) + " and " + std::to_string(t1) + " are not implemented");
	}

	this->Log();
	this->SetNoise( n0->GetNoise() * n1->GetNoise() );
	return this->value;
}

void ModReduceNode::simeval(CircuitGraph& g) {
	if( noiseval != 0 )
		return; // visit only once!

	if( getInputs().size() != 1 ) throw std::logic_error("ModReduce must have one input");

	auto n0 = g.getNodeById(getInputs()[0]);
	n0->simeval(g);
cout << "MODREDUCE:" << endl;
	CircuitNode::PrintLog(cout);
	CircuitNode::Log(GetId(),OpModReduce);
	CircuitNode::PrintLog(cout);
	this->SetNoise( n0->GetNoise() );
	return;
}

template<typename Element>
Value<Element> ModReduceNodeWithValue<Element>::eval(CryptoContext<Element>& cc, CircuitGraphWithValues<Element>& cg) {
	if( this->value.GetType() != UNKNOWN )
		return this->value;

	if( this->getNode()->getInputs().size() != 1 ) throw std::logic_error("ModReduce must have one input");

	auto n0 = cg.getNodeById(this->getNode()->getInputs()[0]);
	Value<Element> v0( n0->eval(cc,cg) );
	auto t0 = v0.GetType();

	if( t0 == VECTOR_INT ) {
		this->value = cc.ModReduce(v0.GetIntVecValue());
	}
	else if( t0 == MATRIX_INT ) {
		this->value = cc.ModReduceMatrix(v0.GetIntMatValue());
	}
	else {
		throw std::logic_error("modreduce for type " + std::to_string(t0) + " is not implemented");
	}

	this->Log();
	this->SetNoise( n0->GetNoise() );
	return this->value;
}

#define TESTANDMAKE(T,TV,n) { T* node = dynamic_cast<T*>(n); if( node != 0 ) return new TV(node); }

template<typename Element>
CircuitNodeWithValue<Element> *ValueNodeFactory( CircuitNode *n ) {
	TESTANDMAKE( ConstInput, ConstInputWithValue<Element>, n );
	TESTANDMAKE( Input, InputWithValue<Element>, n );
	TESTANDMAKE( ModReduceNode, ModReduceNodeWithValue<Element>, n );
	TESTANDMAKE( EvalNegNode, EvalNegNodeWithValue<Element>, n );
	TESTANDMAKE( EvalAddNode, EvalAddNodeWithValue<Element>, n );
	TESTANDMAKE( EvalSubNode, EvalSubNodeWithValue<Element>, n );
	TESTANDMAKE( EvalMultNode, EvalMultNodeWithValue<Element>, n );
	throw std::logic_error("Type not supported in ValueNodeFactory");
}


}
