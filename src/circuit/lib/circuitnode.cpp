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
int	CircuitNodeWithValue<Element>::step;

template<typename Element>
map<usint,map<OpType,int>> CircuitNodeWithValue<Element>::opcountByNode;

template<typename Element>
map<usint,map<OpType,int>>& CircuitNodeWithValue<Element>::GetOperationsMap() { return opcountByNode; }

template<typename Element>
void EvalAddNodeWithValue<Element>::eval(EvaluateMode mode, CryptoContext<Element> cc, CircuitGraphWithValues<Element>& cg) {

	if( this->getInputs().size() < 2 ) throw std::logic_error("Add requires at least 2 inputs");

	auto n0 = cg.getNodeById(this->getInputs()[0]);
	cout << "***** " "ADD 0 evaluating " << *n0 << endl;
	CircuitValue<Element> v0( n0->Evaluate(mode, cc, cg) );
	cout << "***** " "ADD 0 evaluated " << *n0 << endl;
	cout << "***** " << v0 << endl;
	usint noise = n0->GetNoiseActual();
	double runEst = 0;
	usint noiseEst = 0;

	if( mode == CalculateRuntimeEstimates ) {
		noiseEst = n0->GetNoiseEstimate();
		runEst = n0->GetRuntimeEstimate();
		cout << "EvalAdd, node " << this->GetId() << " input 0 " <<  this->getInputs()[0] << " runEst is now " << runEst << endl;
	}

	stringstream ss;
	if( CircuitOpTrace ) {
		ss << "Node " << this->GetId() << ": ";
		ss << "EvalAdd of ";
		ss << this->getInputs()[0] << " (" << v0 << ")";
	}

	for( size_t i=1; i < this->getInputs().size(); i++ ) {
		auto n1 = cg.getNodeById(this->getInputs()[i]);
		CircuitValue<Element> v1( n1->Evaluate(mode, cc, cg) );

		if( CircuitOpTrace ) {
			ss << " and " << this->getInputs()[i] << " (" << v1 << ")";
		}

		if( mode == GetOperationsList ) {
			cout << v0.GetType() << " " << v1.GetType() << endl;

			auto ov = CircuitValue<Element>::OperatorType(OpEvalAdd,v0,v1);
			v0.SetType(ov.GetWire());

			this->opcountByNode[this->GetId()][ov.GetOp()]++;
		}
		else if( mode == CalculateRuntimeEstimates ) {
			noise += n1->GetNoiseEstimate();
			runEst += n1->GetRuntimeEstimate();
			cout << "EvalAdd, node " << this->GetId() << " input " << i << " " << this->getInputs()[i] << " runEst is now " << runEst << endl;
			runEst += this->GetRuntimeEstimateNode();
			cout << "EvalAdd, node " << this->GetId() << " adding local cost, runEst is now " << runEst << endl;

			auto ov = CircuitValue<Element>::OperatorType(OpEvalAdd,v0,v1);
			v0.SetType(ov.GetWire());
		}
		else if( mode == Evaluate ) {
			v0 = v0 + v1;
			noise += n1->GetNoiseActual();
		}
	}

	this->value = v0;

	if( mode == CalculateRuntimeEstimates ) {
		this->SetNoiseEstimate(noiseEst);
		this->SetRuntimeEstimate(runEst);
	}

	if( CircuitOpTrace ) {
		cout << ss.str() << endl;
	}

	this->SetNoiseActual( noise );
	return;
}

template<typename Element>
void EvalSubNodeWithValue<Element>::eval(EvaluateMode mode, CryptoContext<Element> cc, CircuitGraphWithValues<Element>& cg) {

	stringstream ss;
	double runEst = 0;
	usint noiseEst = 0;

	if( this->getInputs().size() == 1 ) {
		// EvalNegate
		auto n0 = cg.getNodeById(this->getInputs()[0]);
		CircuitValue<Element> v0( n0->Evaluate(mode, cc, cg) );

		if( CircuitOpTrace ) {
			ss << "Node " << this->GetId() << ": ";
			ss << "EvalNegate of ";
			ss << this->getInputs()[0] << " (" << v0 << ")";
		}

		if( mode == GetOperationsList ) {
			auto ov = CircuitValue<Element>::OperatorType(OpEvalNeg,v0);
			this->opcountByNode[this->GetId()][ov.GetOp()] = 1;
			this->value.SetType(ov.GetWire());
		}
		else if( mode == CalculateRuntimeEstimates ) {
			this->SetNoiseEstimate( n0->GetNoiseEstimate() );
			runEst = n0->GetRuntimeEstimate();
			cout << "EvalNegate, node " << this->GetId() << " runEst is now " << runEst << endl;
			runEst += this->GetRuntimeEstimateNode();
			cout << "EvalNegate, node " << this->GetId() << " adding local cost, runEst is now " << runEst << endl;
			this->SetRuntimeEstimate(runEst);

			auto ov = CircuitValue<Element>::OperatorType(OpEvalNeg,v0);
			this->value.SetType(ov.GetWire());
		}
		else if( mode == Evaluate ) {
			this->value = -v0;
			this->SetNoiseActual( n0->GetNoiseActual() );
		}

		if( CircuitOpTrace ) {
			cout << ss.str() << endl;
		}

		return;
	}

	if( this->getInputs().size() < 2 ) throw std::logic_error("Subtract requires at least 2 inputs");

	auto n0 = cg.getNodeById(this->getInputs()[0]);
	cout << "***** " "SUB 0 evaluating " << *n0 << endl;
	CircuitValue<Element> v0( n0->Evaluate(mode, cc, cg) );
	cout << "***** " "SUB 0 evaluated " << *n0 << endl;
	usint noise = n0->GetNoiseActual();
	if( mode == CalculateRuntimeEstimates ) {
		noiseEst = n0->GetNoiseEstimate();
		runEst = n0->GetRuntimeEstimate();
		cout << "EvalSub, node " << this->GetId() << " input 0 " <<  this->getInputs()[0] << " runEst is now " << runEst << endl;
	}

	if( CircuitOpTrace ) {
		ss << "Node " << this->GetId() << ": ";
		ss << "EvalSub of ";
		ss << this->getInputs()[0] << " (" << v0 << ")";
	}

	for( size_t i=1; i < this->getInputs().size(); i++ ) {
		auto n1 = cg.getNodeById(this->getInputs()[i]);
		CircuitValue<Element> v1( n1->Evaluate(mode, cc, cg) );
		cout << "***** " "SUB 1 evaluated " << *n1 << endl;

		cout << v0 << endl;
		cout << v1 << endl;

		if( CircuitOpTrace ) {
			ss << " and " << this->getInputs()[i] << " (" << v1 << ")";
		}

		if( mode == GetOperationsList ) {
			auto ov = CircuitValue<Element>::OperatorType(OpEvalSub,v0,v1);
			this->opcountByNode[this->GetId()][ov.GetOp()]++;
			v0.SetType(ov.GetWire());
		}
		else if( mode == CalculateRuntimeEstimates ) {
			noiseEst += n1->GetNoiseEstimate();
			runEst += n1->GetRuntimeEstimate();
			cout << "EvalSub, node " << this->GetId() << " input " << i << " " << this->getInputs()[i] << " runEst is now " << runEst << endl;
			runEst += this->GetRuntimeEstimateNode();
			cout << "EvalSub, node " << this->GetId() << " adding local cost, runEst is now " << runEst << endl;

			auto ov = CircuitValue<Element>::OperatorType(OpEvalSub,v0,v1);
			v0.SetType(ov.GetWire());
			cout << v0 << endl;
		}
		else if( mode == Evaluate ) {
			v0 = v0 - v1;
			noise += n1->GetNoiseActual();
		}
	}

	this->value = v0;

	if( mode == CalculateRuntimeEstimates ) {
		this->SetNoiseEstimate(noiseEst);
		this->SetRuntimeEstimate(runEst);
	}

	if( CircuitOpTrace ) {
		cout << ss.str() << endl;
	}

	this->SetNoiseActual( noise );
	return;
}

template<typename Element>
void EvalMultNodeWithValue<Element>::eval(EvaluateMode mode, CryptoContext<Element> cc, CircuitGraphWithValues<Element>& cg) {

	stringstream ss;
	double runEst = 0;
	usint noiseEst = 0;

	if( this->getInputs().size() > 2 ) {
		usint noiseTotal = 0;
		vector<Ciphertext<Element>> cvec;

		if( CircuitOpTrace ) {
			ss << "Node " << this->GetId() << ": ";
			ss << "EvalMultMany ";
		}

		for( auto nid : this->getInputs() ) {
			auto n = cg.getNodeById(nid);
			noiseTotal += n->GetNoiseActual();
			CircuitValue<Element> v( n->Evaluate(mode, cc, cg) );
			if( mode == CalculateRuntimeEstimates ) {
				noiseEst += n->GetNoiseEstimate();
				runEst += n->GetRuntimeEstimate();
				cout << "EvalMultMany, node " << this->GetId() << " input " << nid << " runEst is now " << runEst << endl;
			}
			ss << nid << " (" << v << ") ";
			if( v.GetType() != CIPHERTEXT ) {
				PALISADE_THROW(type_error, "One of the operands to EvalMultMany is not a Ciphertext");
			}
			cvec.push_back( v.GetCiphertextValue() );
		}

		if( mode == GetOperationsList ) {
			this->opcountByNode[this->GetId()][OpEvalMultMany] = 1;
			this->value.SetType(CIPHERTEXT);
		}
		else if( mode == CalculateRuntimeEstimates ) {
			this->SetNoiseEstimate(noiseEst);
			runEst += this->GetRuntimeEstimateNode();
			cout << "EvalMultMany, node " << this->GetId() << " adding local cost, runEst is now " << runEst << endl;
			this->SetRuntimeEstimate(runEst);

			this->value.SetType(CIPHERTEXT);
		}
		else if( mode == Evaluate ) {
			this->value = cc->EvalMultMany( cvec );
			this->SetNoiseActual( noiseTotal );
		}
	}
	else {
		auto n0 = cg.getNodeById(this->getInputs()[0]);
		auto n1 = cg.getNodeById(this->getInputs()[1]);
		cout << "***** " "MULT 0 evaluating " << *n0 << endl;
		CircuitValue<Element> v0( n0->Evaluate(mode, cc, cg) );
		cout << "***** " "MULT 0 evaluated " << *n0 << endl;
		cout << v0 << endl;
		CircuitValue<Element> v1( n1->Evaluate(mode, cc, cg) );
		cout << "***** " "MULT 1 evaluated " << *n1 << endl;
		cout << v1 << endl;

		if( CircuitOpTrace ) {
			ss << "Node " << this->GetId() << ": ";
			ss << "EvalMult ";
			ss << this->getInputs()[0] << " (" << v0 << ")";
			ss << " and " << this->getInputs()[1] << " (" << v1 << ")";
		}

		if( mode == GetOperationsList ) {
			auto ov = CircuitValue<Element>::OperatorType(OpEvalMult,v0,v1);
			this->opcountByNode[this->GetId()][ov.GetOp()] = 1;
			this->value.SetType(ov.GetWire());
		}
		else if( mode == CalculateRuntimeEstimates ) {
			this->SetNoiseEstimate( n0->GetNoiseEstimate() + n1->GetNoiseEstimate() );
			runEst = n0->GetRuntimeEstimate();
			cout << "EvalMult, node " << this->GetId() << " input 0 runEst is now " << runEst << endl;
			runEst += n1->GetRuntimeEstimate();
			cout << "EvalMult, node " << this->GetId() << " input 1 runEst is now " << runEst << endl;
			runEst += this->GetRuntimeEstimateNode();
			cout << "EvalMult, node " << this->GetId() << " adding local cost, runEst is now " << runEst << endl;
			this->SetRuntimeEstimate( runEst );

			auto ov = CircuitValue<Element>::OperatorType(OpEvalMult,v0,v1);
			this->value.SetType(ov.GetWire());
		}
		else if( mode == Evaluate ) {
			this->value = v0 * v1;
			this->SetNoiseActual( n0->GetNoiseActual() * n1->GetNoiseActual() );
		}
	}

	if( CircuitOpTrace ) {
		cout << ss.str() << endl;
	}

	return;
}

template<typename Element>
void EvalRShiftNodeWithValue<Element>::eval(EvaluateMode mode, CryptoContext<Element> cc, CircuitGraphWithValues<Element>& cg) {

	if( this->getInputs().size() != 2 ) throw std::logic_error("RShift requires 2 inputs");

	auto n0 = cg.getNodeById(this->getInputs()[0]);
	auto n1 = cg.getNodeById(this->getInputs()[1]);
	CircuitValue<Element> v0( n0->Evaluate(mode, cc, cg) );
	CircuitValue<Element> v1( n1->Evaluate(mode, cc, cg) );

	if( mode == GetOperationsList ) {
		this->opcountByNode[this->GetId()][OpEvalRightShift] = 1;
		this->value.SetType(CIPHERTEXT);
	}
	else if( mode == CalculateRuntimeEstimates ) {
		this->SetNoiseEstimate( n0->GetNoiseEstimate() + n1->GetNoiseEstimate() );
		double runEst = n0->GetRuntimeEstimate();
		cout << "EvalRShift, node " << this->GetId() << " input 0 runEst is now " << runEst << endl;
		runEst += n1->GetRuntimeEstimate();
		cout << "EvalRShift, node " << this->GetId() << " input 1 runEst is now " << runEst << endl;
		runEst += this->GetRuntimeEstimateNode();
		cout << "EvalRShift, node " << this->GetId() << " adding local cost, runEst is now " << runEst << endl;
		this->SetRuntimeEstimate( runEst );

		this->value.SetType(CIPHERTEXT);
	}
	else if( mode == Evaluate ) {
		this->value = v0 >> v1;
		this->SetNoiseActual( n0->GetNoiseActual() * n1->GetNoiseActual() );
	}

	return;
}

template<typename Element>
void EvalInnerProdNodeWithValue<Element>::eval(EvaluateMode mode, CryptoContext<Element> cc, CircuitGraphWithValues<Element>& cg) {

	if( this->getInputs().size()%2 != 0 ) throw std::logic_error("InnerProduct requires even number of inputs");

	int vecsize = this->getInputs().size()/2;
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

	double runEst = 0;
	usint noiseEst = 0;
	for( auto i = 0; i < this->getInputs().size(); i++ ) {
		if( i == vecsize ) {
			vecp = &vec2;
			if( CircuitOpTrace ) {
				ss << "} and {\n" ;
			}
		}

		auto n = cg.getNodeById(this->getInputs()[i]);
		CircuitValue<Element> v( n->Evaluate(mode, cc, cg) );
		if( v.GetType() != CIPHERTEXT ) {
			throw std::logic_error("InnerProduct only works on ciphertexts");
		}
		if( mode == CalculateRuntimeEstimates ) {
			noiseEst += n->GetNoiseEstimate();
			runEst += n->GetRuntimeEstimate();
			cout << "EvalInnerProduct, node " << this->GetId() << " input, runEst is now " << runEst << endl;
		}

		if( CircuitOpTrace ) {
			ss << this->getInputs()[i] << " (" << v << ")\n";
		}
		vecp->push_back( v.GetCiphertextValue() );
	}

	if( mode == GetOperationsList ) {
		this->opcountByNode[this->GetId()][OpEvalMerge] = 2;
		this->opcountByNode[this->GetId()][OpEvalInnerProduct] = 1;
		this->value.SetType(CIPHERTEXT);
	}
	else if( mode == CalculateRuntimeEstimates ) {
		runEst += this->GetRuntimeEstimateNode();
		cout << "EvalInnerProduct, node " << this->GetId() << " adding local cost, runEst is now " << runEst << endl;
		this->SetRuntimeEstimate(runEst);
		this->SetNoiseEstimate(noiseEst);

		this->value.SetType(CIPHERTEXT);
	}
	else if( mode == Evaluate ) {

		auto arg1 = cc->EvalMerge(vec1);
		auto arg2 = cc->EvalMerge(vec2);

		if( CircuitOpTrace ) {
			ss << "}\nEvalInnerProduct of results, depth " << innerProdDepth;
		}

		this->value = cc->EvalInnerProduct(arg1, arg2, innerProdDepth);

		if( CircuitOpTrace ) {
			cout << ss.str() << endl;
		}

		// FIXME this->SetNoiseActual( ???? );
	}
	cout << "node " << this->getNode()->GetId() << " type now " << this->value.GetType() << endl;

	return;
}

template<typename Element>
void ModReduceNodeWithValue<Element>::eval(EvaluateMode mode, CryptoContext<Element> cc, CircuitGraphWithValues<Element>& cg) {

	if( this->getInputs().size() != 1 ) throw std::logic_error("ModReduce must have one input");

	auto n0 = cg.getNodeById(this->getInputs()[0]);
	CircuitValue<Element> v0( n0->Evaluate(mode, cc, cg) );

	if( mode == GetOperationsList ) {
		auto ov = CircuitValue<Element>::OperatorType(OpModReduce,v0);
		this->opcountByNode[this->GetId()][ov.GetOp()] = 1;
		this->value.SetType(ov.GetWire());
	}
	else if( mode == CalculateRuntimeEstimates ) {
		double runEst = n0->GetRuntimeEstimate();
		cout << "ModReduce, node " << this->GetId() << " input runEst is now " << runEst << endl;
		runEst += this->GetRuntimeEstimateNode();
		cout << "ModReduce, node " << this->GetId() << " adding local cost, runEst is now " << runEst << endl;
		this->SetRuntimeEstimate( runEst );
		this->SetNoiseEstimate( n0->GetNoiseEstimate() );

		auto ov = CircuitValue<Element>::OperatorType(OpModReduce,v0);
		this->value.SetType(ov.GetWire());
	}
	else if( mode == Evaluate ) {

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

		this->SetNoiseActual( n0->GetNoiseActual() );
	}
	return;
}

#define TESTANDMAKE(T,TV,n) { T* node = dynamic_cast<T*>(n); if( node != 0 ) return new TV(n); }

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
