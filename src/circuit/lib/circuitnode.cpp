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
ostream& CircuitNodeWithValue<Element>::Display(ostream& out, LPPrivateKey<Element> k)
{
	out << this->GetId() << "  [label=\"" << this->GetId() << "\\n";
	if( this->getNode()->getInputDepth() != 0 )
		out << "(d=" + std::to_string(this->getNode()->getInputDepth()) + ")\\n";
	out << this->getNodeLabel();
	if( this->IsOutput() ) {
		out << "(output)\\n";
	}

	out << "\\n(noise=" << this->GetNoise() << ")\\n";

	const Value<Element>& val = this->getValue();
	if( val.GetType() != UNKNOWN ) {
		val.Display(out, k);
	}

	out << "\"]; ";

	const vector<usint>& nodeInputs = this->getNode()->getInputs();
	for( usint input : nodeInputs )
		out << input << " -> " << this->GetId() << "; ";

	return out;
}

void CircuitNode::CircuitVisit(CircuitGraph& g) {
	if( Visited() )
		return;

	for( usint in : inputs ) {
		CircuitNode *n = g.getNodeById(in);
		n->CircuitVisit(g);
	}

	this->MarkEstimate();
	Visit();
	return;
}

template<typename Element>
void CircuitNodeWithValue<Element>::CircuitVisit(CircuitGraphWithValues<Element>& g) {
	if( Visited() )
		return;

	for( usint in : this->getNode()->getInputs() ) {
		CircuitNodeWithValue<Element> *n = g.getNodeById(in);
		n->CircuitVisit(g);
	}

	Visit();
	return;
}

// note that for our purposes here, INT and VECTOR_INT can be considered the same thing
// since an INT is simply a vector with one entry and the rest zeroes

void EvalAddNode::simeval(CircuitGraph& g, vector<CircuitSimulation>& ops) {
	if( Visited() )
		return; // visit only once!

	Visit();

	if( getInputs().size() < 2 ) throw std::logic_error("Add requires at least 2 inputs");

	auto n0 = g.getNodeById(getInputs()[0]);
	n0->simeval(g, ops);
	usint noise = n0->GetNoise();

	for( size_t i=1; i < getInputs().size(); i++ ) {
		auto n1 = g.getNodeById(getInputs()[i]);
		n1->simeval(g, ops);

		noise += n1->GetNoise();
	}

	CircuitNode::Log(ops,GetId(),OpEvalAdd);
	this->SetNoise( noise );
	return;
}

template<typename Element>
Value<Element> EvalAddNodeWithValue<Element>::eval(CryptoContext<Element> cc, CircuitGraphWithValues<Element>& cg) {
	if( this->value.GetType() != UNKNOWN )
		return this->value;

	if( this->getNode()->getInputs().size() < 2 ) throw std::logic_error("Add requires at least 2 inputs");

	auto n0 = cg.getNodeById(this->getNode()->getInputs()[0]);
	Value<Element> v0( n0->eval(cc,cg) );
	usint noise = n0->GetNoise();

	stringstream ss;
	if( CircuitOpTrace ) {
		ss << "Node " << this->GetId() << ": ";
		ss << "EvalAdd of ";
		ss << this->getNode()->getInputs()[0] << " (" << v0 << ")";
	}

	for( size_t i=1; i < this->getNode()->getInputs().size(); i++ ) {
		auto n1 = cg.getNodeById(this->getNode()->getInputs()[i]);
		Value<Element> v1( n1->eval(cc,cg) );

		if( CircuitOpTrace ) {
			ss << " and " << this->getNode()->getInputs()[i] << " (" << v1 << ")";
		}

		v0 = v0 + v1;

		noise += n1->GetNoise();
	}

	this->value = v0;

	if( CircuitOpTrace ) {
		cout << ss.str() << endl;
	}

	this->Log();
	this->SetNoise( noise );
	return this->value;
}

void EvalSubNode::simeval(CircuitGraph& g, vector<CircuitSimulation>& ops) {
	if( Visited() )
		return; // visit only once!

	Visit();

	if( getInputs().size() == 1 ) {
		auto n0 = g.getNodeById(getInputs()[0]);
		n0->simeval(g,ops);
		this->SetNoise( n0->GetNoise() );
		CircuitNode::Log(ops,GetId(),OpEvalNeg);
		return;
	}

	if( getInputs().size() < 2 ) throw std::logic_error("Sub requires at least 2 inputs");

	auto n0 = g.getNodeById(getInputs()[0]);
	n0->simeval(g,ops);
	usint noise = n0->GetNoise();

	for( size_t i=1; i < getInputs().size(); i++ ) {
		auto n1 = g.getNodeById(getInputs()[i]);
		n1->simeval(g,ops);

		noise += n1->GetNoise();
	}

	CircuitNode::Log(ops,GetId(),OpEvalSub);
	this->SetNoise( noise );
	return;
}

template<typename Element>
Value<Element> EvalSubNodeWithValue<Element>::eval(CryptoContext<Element> cc, CircuitGraphWithValues<Element>& cg) {
	if( this->value.GetType() != UNKNOWN )
		return this->value;

	stringstream ss;

	if( this->getNode()->getInputs().size() == 1 ) {
		// EvalNegate
		auto n0 = cg.getNodeById(this->getNode()->getInputs()[0]);
		Value<Element> v0( n0->eval(cc,cg) );

		if( CircuitOpTrace ) {
			ss << "Node " << this->GetId() << ": ";
			ss << "EvalNegate of ";
			ss << this->getNode()->getInputs()[0] << " (" << v0 << ")";
		}

		this->value = -v0;
		this->SetNoise( n0->GetNoise() );

		if( CircuitOpTrace ) {
			cout << ss.str() << endl;
		}
		this->Log();

		return this->value;
	}

	if( this->getNode()->getInputs().size() < 2 ) throw std::logic_error("Subtract requires at least 2 inputs");

	auto n0 = cg.getNodeById(this->getNode()->getInputs()[0]);
	Value<Element> v0( n0->eval(cc,cg) );
	usint noise = n0->GetNoise();

	if( CircuitOpTrace ) {
		ss << "Node " << this->GetId() << ": ";
		ss << "EvalSub of ";
		ss << this->getNode()->getInputs()[0] << " (" << v0 << ")";
	}

	for( size_t i=1; i < this->getNode()->getInputs().size(); i++ ) {
		auto n1 = cg.getNodeById(this->getNode()->getInputs()[i]);
		Value<Element> v1( n1->eval(cc,cg) );

		if( CircuitOpTrace ) {
			ss << " and " << this->getNode()->getInputs()[i] << " (" << v1 << ")";
		}

		v0 = v0 - v1;

		noise += n1->GetNoise();
	}

	this->value = v0;

	if( CircuitOpTrace ) {
		cout << ss.str() << endl;
	}

	this->Log();
	this->SetNoise( noise );
	return this->value;
}

void EvalMultNode::simeval(CircuitGraph& g, vector<CircuitSimulation>& ops) {
	if( Visited() )
		return; // visit only once!

	Visit();
	if( getInputs().size() > 2 ) {
		usint noiseTotal = 0;
		for( auto nid : getInputs() ) {
			auto n = g.getNodeById(nid);
			n->simeval(g, ops);
			noiseTotal += n->GetNoise();
		}

		CircuitNode::Log(ops,GetId(),OpEvalMultMany);
		this->SetNoise( noiseTotal );
	}
	else {
		auto n0 = g.getNodeById(getInputs()[0]);
		auto n1 = g.getNodeById(getInputs()[1]);
		n0->simeval(g,ops);
		n1->simeval(g,ops);

		CircuitNode::Log(ops,GetId(),OpEvalMult);
		this->SetNoise( n0->GetNoise() + n1->GetNoise() );
	}
	return;
}

template<typename Element>
Value<Element> EvalMultNodeWithValue<Element>::eval(CryptoContext<Element> cc, CircuitGraphWithValues<Element>& cg) {
	if( this->value.GetType() != UNKNOWN )
		return this->value;

	stringstream ss;

	if( this->getNode()->getInputs().size() > 2 ) {
		usint noiseTotal = 0;
		vector<Ciphertext<Element>> cvec;

		if( CircuitOpTrace ) {
			ss << "Node " << this->GetId() << ": ";
			ss << "EvalMultMany ";
		}

		for( auto nid : this->getNode()->getInputs() ) {
			auto n = cg.getNodeById(nid);
			noiseTotal += n->GetNoise();
			Value<Element> v( n->eval(cc,cg) );
			ss << nid << " (" << v << ") ";
			if( v.GetType() != CIPHERTEXT ) {
				PALISADE_THROW(type_error, "One of the operands to EvalMultMany is not a Ciphertext");
			}
			cvec.push_back( v.GetCiphertextValue() );
		}

		this->value = cc->EvalMultMany( cvec );

		this->SetNoise( noiseTotal );
	}
	else {
		auto n0 = cg.getNodeById(this->getNode()->getInputs()[0]);
		auto n1 = cg.getNodeById(this->getNode()->getInputs()[1]);
		Value<Element> v0( n0->eval(cc,cg) );
		Value<Element> v1( n1->eval(cc,cg) );

		if( CircuitOpTrace ) {
			ss << "Node " << this->GetId() << ": ";
			ss << "EvalMult ";
			ss << this->getNode()->getInputs()[0] << " (" << v0 << ")";
			ss << " and " << this->getNode()->getInputs()[1] << " (" << v1 << ")";
		}

		this->value = v0 * v1;

		this->SetNoise( n0->GetNoise() * n1->GetNoise() );
	}

	if( CircuitOpTrace ) {
		cout << ss.str() << endl;
	}

	this->Log();
	return this->value;
}

void EvalRShiftNode::simeval(CircuitGraph& g, vector<CircuitSimulation>& ops) {
	if( Visited() )
		return; // visit only once!

	Visit();
	if( getInputs().size() != 2 ) throw std::logic_error("RShift requires 2 inputs");

	auto n0 = g.getNodeById(getInputs()[0]);
	auto n1 = g.getNodeById(getInputs()[1]);
	n0->simeval(g,ops);
	n1->simeval(g,ops);

	CircuitNode::Log(ops,GetId(),OpEvalMult);
	this->SetNoise( n0->GetNoise() + n1->GetNoise() );
	return;
}

template<typename Element>
Value<Element> EvalRShiftNodeWithValue<Element>::eval(CryptoContext<Element> cc, CircuitGraphWithValues<Element>& cg) {
	if( this->value.GetType() != UNKNOWN )
		return this->value;

	if( this->getNode()->getInputs().size() != 2 ) throw std::logic_error("RShift requires 2 inputs");

	auto n0 = cg.getNodeById(this->getNode()->getInputs()[0]);
	auto n1 = cg.getNodeById(this->getNode()->getInputs()[1]);
	Value<Element> v0( n0->eval(cc,cg) );
	Value<Element> v1( n1->eval(cc,cg) );

	this->value = v0 >> v1;

	this->Log();
	this->SetNoise( n0->GetNoise() * n1->GetNoise() );
	return this->value;
}

void EvalInnerProdNode::simeval(CircuitGraph& g, vector<CircuitSimulation>& ops) {
	if( Visited() )
		return; // visit only once!

	Visit();
	if( getInputs().size()%2 != 0 ) throw std::logic_error("InnerProduct requires even number of inputs");

	auto n0 = g.getNodeById(getInputs()[0]);
	auto n1 = g.getNodeById(getInputs()[1]);
	n0->simeval(g,ops);
	n1->simeval(g,ops);

	CircuitNode::Log(ops,GetId(),OpEvalMult);
	this->SetNoise( n0->GetNoise() + n1->GetNoise() );
	return;
}

template<typename Element>
Value<Element> EvalInnerProdNodeWithValue<Element>::eval(CryptoContext<Element> cc, CircuitGraphWithValues<Element>& cg) {
	if( this->value.GetType() != UNKNOWN )
		return this->value;

	if( this->getNode()->getInputs().size()%2 != 0 ) throw std::logic_error("InnerProduct requires even number of inputs");

	int vecsize = this->getNode()->getInputs().size()/2;
	auto logsize = log2(vecsize);
	int logfl = (int)floor(logsize);
	if( logfl != logsize ) // power of 2
		logfl++;
	int innerProdDepth = 1;
	for( int ii=0; ii<logfl; ii++ )
		innerProdDepth *= 2;

	vector<Ciphertext<Element>> vec1;
	vec1.reserve(vecsize);
	vector<Ciphertext<Element>> vec2;
	vec2.reserve(vecsize);
	vector<Ciphertext<Element>>* vecp = &vec1;

	stringstream ss;

	if( CircuitOpTrace ) {
		ss << "Node " << this->GetId() << ": ";
		ss << "EvalMerge: {\n";
	}

	for( auto i = 0; i < this->getNode()->getInputs().size(); i++ ) {
		if( i == vecsize ) {
			vecp = &vec2;
			if( CircuitOpTrace ) {
				ss << "} and {\n" ;
			}
		}

		Value<Element> v( cg.getNodeById(this->getNode()->getInputs()[i])->eval(cc, cg) );
		if( v.GetType() != CIPHERTEXT ) {
			throw std::logic_error("InnerProduct only works on ciphertexts");
		}

		if( CircuitOpTrace ) {
			ss << this->getNode()->getInputs()[i] << " (" << v << ")\n";
		}
		vecp->push_back( v.GetCiphertextValue() );
	}


	auto arg1 = cc->EvalMerge(vec1);
	auto arg2 = cc->EvalMerge(vec2);

	if( CircuitOpTrace ) {
		ss << "}\nEvalInnerProduct (";
		ss <<  arg1;
		ss << ")\n and (" << arg2 << ")\n depth " << innerProdDepth;
	}

	this->value = cc->EvalInnerProduct(arg1, arg2, innerProdDepth);

	if( CircuitOpTrace ) {
		cout << ss.str() << endl;
	}

	this->Log();
	// FIXME this->SetNoise( ???? );
	return this->value;
}

void ModReduceNode::simeval(CircuitGraph& g, vector<CircuitSimulation>& ops) {
	if( Visited() )
		return; // visit only once!

	Visit();
	if( getInputs().size() != 1 ) throw std::logic_error("ModReduce must have one input");

	auto n0 = g.getNodeById(getInputs()[0]);
	n0->simeval(g,ops);

	CircuitNode::Log(ops,GetId(),OpModReduce);
	this->SetNoise( n0->GetNoise() );
	return;
}

template<typename Element>
Value<Element> ModReduceNodeWithValue<Element>::eval(CryptoContext<Element> cc, CircuitGraphWithValues<Element>& cg) {
	if( this->value.GetType() != UNKNOWN )
		return this->value;

	if( this->getNode()->getInputs().size() != 1 ) throw std::logic_error("ModReduce must have one input");

	auto n0 = cg.getNodeById(this->getNode()->getInputs()[0]);
	Value<Element> v0( n0->eval(cc,cg) );

	switch( v0.GetType() ) {
	case PLAINTEXT:
		this->value = v0;
		break;

	case CIPHERTEXT:
		this->value = cc->ModReduce(v0.GetCiphertextValue());
		break;

	case MATRIX_RAT:
		this->value = cc->ModReduceMatrix(v0.GetMatrixRtValue());
		break;

	default:
		break;
	}

	this->Log();
	this->SetNoise( n0->GetNoise() );
	return this->value;
}

#define TESTANDMAKE(T,TV,n) { T* node = dynamic_cast<T*>(n); if( node != 0 ) return new TV(node); }

template<typename Element>
CircuitNodeWithValue<Element> *CircuitNodeWithValue<Element>::ValueNodeFactory( CircuitNode *n ) {
	TESTANDMAKE( Input, InputWithValue<Element>, n );
	TESTANDMAKE( ConstInt, ConstIntWithValue<Element>, n );
	TESTANDMAKE( ConstPtxt, ConstPtxtWithValue<Element>, n );
	TESTANDMAKE( ModReduceNode, ModReduceNodeWithValue<Element>, n );
	TESTANDMAKE( EvalAddNode, EvalAddNodeWithValue<Element>, n );
	TESTANDMAKE( EvalSubNode, EvalSubNodeWithValue<Element>, n );
	TESTANDMAKE( EvalMultNode, EvalMultNodeWithValue<Element>, n );
	TESTANDMAKE( EvalRShiftNode, EvalRShiftNodeWithValue<Element>, n);
	TESTANDMAKE( EvalInnerProdNode, EvalInnerProdNodeWithValue<Element>, n);
	throw std::logic_error("Type not supported in ValueNodeFactory");
}


}
