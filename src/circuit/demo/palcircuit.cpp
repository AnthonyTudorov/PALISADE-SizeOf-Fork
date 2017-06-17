/**
 * @file palcircuit.cpp -- Test program to demo parsing, estimating, and executing circuits
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
 * Demonstrates how to parse and evaluate circuits
 *
 */

#include "palisade.h"
#include "cryptocontextgen.h"
#include "palisadecircuit.h"
using namespace lbcrypto;
using std::cout;

#include <fstream>
using std::ostream;

#include "parsedriver.h"

#include "circuitnode.cpp"
#include "circuitgraph.cpp"

namespace lbcrypto {
template class CircuitGraphWithValues<ILVector2n>;
template class CircuitNodeWithValue<ILVector2n>;
}

void usage() {
	cout << "Arguments are" << endl;
	cout << "-d  --  debug mode on the parse" << endl;
	cout << "-ginput  --  print a graph of the input circuit in DOT format (for use with graphviz)" << endl;
	cout << "-gproc  --  print the circuit in DOT format for use with graphviz" << endl;
	cout << "-gresult  --  print the circuit in DOT format for use with graphviz" << endl;
	cout << "-elist=filename  --  save information needed for estimating in file filename; stop after generating" << endl;
	cout << "-v  --  verbose details about the circuit" << endl;
	cout << "-h  --  this message" << endl;
}

int
main(int argc, char *argv[])
{
	const usint MAXVECS = 30;

	//CryptoContext<ILVector2n> cc = GenCryptoContextElementArrayNull(8, 5, 8, 10);
	CryptoContext<ILVector2n> cc = GenCryptoContextElementNull(8,32);
	//CryptoContext<ILVector2n> cc = GenCryptoContextElementFV(32,32);
	cc.Enable(LEVELEDSHE);

//	IntPlaintextEncoding vecs[] = {
//			{ 1,2,3,5 },
//			{ 1,2,3,7 }
//	};
	IntPlaintextEncoding ints[] = { { 7 }, { 3 } };

	LPKeyPair<ILVector2n> kp = cc.KeyGen();
	cc.EvalMultKeyGen(kp.secretKey);

	//	vector< vector<shared_ptr<Ciphertext<ILVector2n>>> > cipherVecs;
	//	for( size_t i = 0; i < sizeof(vecs)/sizeof(vecs[0]); i++ )
	//		cipherVecs.push_back( cc.Encrypt(kp.publicKey, vecs[i]) );

	vector< vector<shared_ptr<Ciphertext<ILVector2n>>> > intVecs;
	for( size_t i = 0; i < sizeof(ints)/sizeof(ints[0]); i++ )
		intVecs.push_back( cc.Encrypt(kp.publicKey, ints[i]) );

	vector< vector<shared_ptr<Ciphertext<ILVector2n>>> > cipherVecs;
	for( usint i = 0; i < MAXVECS; i++ )
		cipherVecs.push_back( cc.Encrypt(kp.publicKey, IntPlaintextEncoding({i+1})) );

	Matrix<Ciphertext<ILVector2n>>	mat([cc](){return make_unique<Ciphertext<ILVector2n> >(cc);},3,3);

	CircuitIO<ILVector2n> inputs;

	bool debug_parse = false;
	bool print_input_graph = false;
	bool print_preproc_graph = false;
	bool print_result_graph = false;
	bool verbose = false;
	bool evaluation_list_mode = false;
	ofstream	evalListF;
	for( int i=1; i<argc; i++ ) {
		string arg(argv[i]);
		string argf(arg);

		// split by = sign
		auto epos = arg.find('=');
		arg = arg.substr(0, epos);
		argf = argf.substr(epos+1);

		if( arg == "-d" ) {
			debug_parse = true;
			continue;
		}
		if( arg == "-ginput" ) {
			print_input_graph = true;
			continue;
		}
		if( arg == "-gproc" ) {
			print_preproc_graph = true;
			continue;
		}
		if( arg == "-gresult" ) {
			print_result_graph = true;
			continue;
		}
		if( arg == "-v" ) {
			verbose = true;
			continue;
		}
		if( arg == "-h" ) {
			usage();
			return 0;
		}
		if( arg == "-elist" ) {
			evaluation_list_mode = true;
			evalListF.open(argf, ofstream::out);
			if( !evalListF.is_open() ) {
				cout << "Unable to open file " << argf << endl;
				return 1;
			}
			continue;
		}
		if( arg[0] == '-' ) { // an unrecognized arg
			usage();
			return 0;
		}

		if( verbose )
			cout << "Crypto Parameters used:" << endl << *cc.GetCryptoParameters() << endl;

		if( evaluation_list_mode ) {
			Serialized serObj;
			serObj.SetObject();
			if( cc.Serialize(&serObj) == false ) {
				cout << "Can't serialize CryptoContext" << endl;
				return 1;
			}
			SerializableHelper::SerializationToStream(serObj, evalListF);
		}

		pdriver driver(debug_parse);

		auto res = driver.parse(argv[i]);
		if( res != 0 ) {
			cout << "Parse error" << endl;
			return 1;
		}

		if( verbose ) {
			cout << "Circuit parsed" << endl;
		}

		if( print_input_graph )
			driver.graph.DisplayGraph();

		if( verbose ) cout << "Setting up" << endl;
		driver.graph.Preprocess();

		if( print_preproc_graph )
			driver.graph.DisplayGraph();

		if( evaluation_list_mode ) {
			driver.graph.GenerateOperationList();
			if( verbose ) {
				cout << "The operations used are:" << endl;
				CircuitNode::PrintOperationSet(cout);
			}
			CircuitNode::PrintOperationSet(evalListF);
			evalListF.close();
			return 0;
		}

		PalisadeCircuit<ILVector2n>	cir(cc, driver.graph);

		if( verbose )
			cir.CircuitDump();

		auto intypes = cir.GetGraph().GetInputTypes();
		if( verbose ) {
			cout << "Circuit takes " << intypes.size() << " inputs:" <<endl;
			for( size_t i = 0; i < intypes.size(); i++ ) {
				cout << "input " << i << ": type " << intypes[i] << endl;
			}
		}

		//
		size_t curVec = 0, maxVec = MAXVECS; //sizeof(vecs)/sizeof(vecs[0]);
		size_t curInt = 0, maxInt = sizeof(ints)/sizeof(ints[0]);

		for( size_t i = 0; i < intypes.size(); i++ ) {
			//if( verbose ) cout << "input " << i << ": value ";

			switch(intypes[i]) {
			case INT:
				if( curInt == maxInt )
					throw std::logic_error("out of ints");
				inputs[i] = intVecs[curInt++][0];
				//if( verbose ) cout << ints[i] << endl;
				break;

			case VECTOR_INT:
				if( curVec == maxVec )
					throw std::logic_error("out of vecs");
				inputs[i] = cipherVecs[curVec++][0];
				//if( verbose ) cout << vecs[i] << endl;
				break;

			default:
				throw std::logic_error("type not supported");
			}
		}

		vector<TimingInfo>	times;
		cc.StartTiming(&times);

		CircuitNodeWithValue<ILVector2n>::ResetSimulation();

		CircuitIO<ILVector2n> outputs = cir.CircuitEval(inputs, verbose);

		cc.StopTiming();

		if( verbose )
			CircuitNodeWithValue<ILVector2n>::PrintLog(cout);

		for( auto& out : outputs ) {
			IntPlaintextEncoding result;

			cout << "For output " << out.first << endl;
			cc.Decrypt(kp.secretKey, {out.second.GetIntVecValue()}, &result);

			cout << result << endl;
		}

		if( print_result_graph ) {
			cir.GetGraph().DisplayDecryptedGraph(cc, kp.secretKey);
		}

		if( verbose ) {
			cout << "Timing Information:" << endl;
			for( size_t i = 0; i < times.size(); i++ ) {
				cout << times[i] << endl;
			}
		}
	}

	return 0;
}

