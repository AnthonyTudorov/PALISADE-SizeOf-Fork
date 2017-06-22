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
template class CircuitGraphWithValues<ILDCRT2n>;
template class CircuitNodeWithValue<ILDCRT2n>;
}

void usage() {
	cout << "Arguments are" << endl;
	cout << "-d  --  debug mode on the parse" << endl;
	cout << "-ginput[=file]  --  print a graph of the input circuit, DOT format" << endl;
	cout << "-gproc[=file]  --  print a graph of the preprocessed input circuit, DOT format" << endl;
	cout << "-gresult[=file]  --  print a graph of the result of executing the circuit, DOT format" << endl;
	cout << "-elist=filename  --  save information needed for estimating in file filename; stop after generating" << endl;
	cout << "-estats=filename  --  use this information for estimating runtime" << endl;
	cout << "-v  --  verbose details about the circuit" << endl;
	cout << "-h  --  this message" << endl;
}


void PrintOperationSet(ostream& out, vector<CircuitSimulation>& timings) {
	map<OpType,bool> ops;
	for( int i=0; i < timings.size(); i++ )
		ops[ timings[i].op ] = true;
	for( auto op : ops )
		out << op.first << endl;
}

void PrintLog(ostream& out, vector<CircuitSimulation>& timings) {
	out << timings.size() << " steps" << endl;
	for( int i=0; i < timings.size(); i++ )
		out << i << ": " << timings[i] << endl;
}


int
main(int argc, char *argv[])
{
	const usint MAXVECS = 30;

	CryptoContext<ILDCRT2n> cc = GenCryptoContextElementArrayNull(8, 5, 32, 10);
//	CryptoContext<ILDCRT2n> cc = GenCryptoContextElementNull(8,32);
	//CryptoContext<ILDCRT2n> cc = GenCryptoContextElementLTV(8,32);
	cc.Enable(LEVELEDSHE);

//	IntPlaintextEncoding vecs[] = {
//			{ 1,2,3,5 },
//			{ 1,2,3,7 }
//	};
	IntPlaintextEncoding ints[] = { { 7 }, { 3 } };

	LPKeyPair<ILDCRT2n> kp = cc.KeyGen();
	cc.EvalMultKeyGen(kp.secretKey);

	//	vector< vector<shared_ptr<Ciphertext<ILDCRT2n>>> > cipherVecs;
	//	for( size_t i = 0; i < sizeof(vecs)/sizeof(vecs[0]); i++ )
	//		cipherVecs.push_back( cc.Encrypt(kp.publicKey, vecs[i]) );

	vector< vector<shared_ptr<Ciphertext<ILDCRT2n>>> > intVecs;
	for( size_t i = 0; i < sizeof(ints)/sizeof(ints[0]); i++ )
		intVecs.push_back( cc.Encrypt(kp.publicKey, ints[i]) );

	vector< vector<shared_ptr<Ciphertext<ILDCRT2n>>> > cipherVecs;
	for( usint i = 0; i < MAXVECS; i++ )
		cipherVecs.push_back( cc.Encrypt(kp.publicKey, IntPlaintextEncoding({i+1})) );

	Matrix<IntPlaintextEncoding> mat([](){return make_unique<IntPlaintextEncoding>();},3,3);

	shared_ptr<Matrix<RationalCiphertext<ILDCRT2n>>> emat = cc.EncryptMatrix(kp.publicKey, mat);

	CircuitIO<ILDCRT2n> inputs;

	bool debug_parse = false;
	bool print_input_graph = false;
	bool print_preproc_graph = false;
	bool print_result_graph = false;
	bool verbose = false;
	bool evaluation_list_mode = false;
	bool evaluation_run_mode = false;
	ofstream	evalListF;
	ifstream	evalStatF;
	ostream	*inGraph = &cout;
	ostream	*procGraph = &cout;
	ostream	*resultGraph = &cout;
	ofstream inGF, procGF, resultGF;

	// Process user args
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
			if( argf.size() > 0 ) {
				inGF.open(argf, ostream::out);
				if( !inGF.is_open() ) {
					cout << "Unable to open file " << argf << endl;
					return 1;
				}
				inGraph = &inGF;
			}
			continue;
		}
		if( arg == "-gproc" ) {
			print_preproc_graph = true;
			if( argf.size() > 0 ) {
				procGF.open(argf, ostream::out);
				if( !procGF.is_open() ) {
					cout << "Unable to open file " << argf << endl;
					return 1;
				}
				procGraph = &procGF;
			}
			continue;
		}
		if( arg == "-gresult" ) {
			print_result_graph = true;
			if( argf.size() > 0 ) {
				resultGF.open(argf, ostream::out);
				if( !resultGF.is_open() ) {
					cout << "Unable to open file " << argf << endl;
					return 1;
				}
				resultGraph = &resultGF;
			}
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
		if( arg == "-estats" ) {
			evaluation_run_mode = true;
			evalStatF.open(argf, ofstream::in);
			if( !evalStatF.is_open() ) {
				cout << "Unable to open file " << argf << endl;
				return 1;
			}
			continue;
		}
		if( arg[0] == '-' ) { // an unrecognized arg
			usage();
			return 1;
		}

		if( evaluation_list_mode && evaluation_run_mode ) {
			cout << "Cannot specify both -elist and -estats" << endl;
			return 1;
		}

		// Prepare to process the graph
//		if( verbose )
//			cout << "Crypto Parameters used:" << endl << *cc.GetCryptoParameters() << endl;

		// when in evaluation mode (preparing to estimate/run, then stop), save the CryptoContext
		if( evaluation_list_mode ) {
			Serialized serObj;
			serObj.SetObject();
			if( cc.Serialize(&serObj) == false ) {
				cout << "Can't serialize CryptoContext" << endl;
				return 1;
			}
			SerializableHelper::SerializationToStream(serObj, evalListF);
		}

		// when generating timing estimates, need to read in the Context and the timings
		map<OpType,TimingStatistics> timings;
		if( evaluation_run_mode ) {
			Serialized serObj;
			if( SerializableHelper::StreamToSerialization(evalStatF, &serObj) == false ) {
				cout << "Input file does not begin with a serialization" << endl;
				return 1;
			}

			if( CryptoContextFactory<ILDCRT2n>::DeserializeAndValidateParams(cc, serObj) == false ) {
				cout << "Crypto context in file does not match" << endl;
			}

			while( SerializableHelper::StreamToSerialization(evalStatF, &serObj) == true ) {
				TimingStatistics stat;
				stat.Deserialize(serObj);
				timings[ stat.operation ] = stat;
			}
			evalStatF.close();
		}

		// Parse the graph
		pdriver driver(debug_parse);

		auto res = driver.parse(argv[i]);
		if( res != 0 ) {
			cout << "Parse error" << endl;
			return 1;
		}

		if( verbose ) {
			cout << "Circuit parsed" << endl;
		}

		if( print_input_graph ) {
			driver.graph.DisplayGraph(inGraph);
			if( inGF.is_open() )
				inGF.close();
		}

		// assign depths and optimize if you can
		if( verbose ) cout << "Preprocessing" << endl;
		driver.graph.Preprocess();

		if( print_preproc_graph ) {
			driver.graph.DisplayGraph(procGraph);
			if( procGF.is_open() )
				procGF.close();
		}

		// to do estimates we need to know what functions we called; write them out and finish up
		if( evaluation_list_mode ) {
			vector<CircuitSimulation> opslist;
			driver.graph.GenerateOperationList(opslist);
			if( verbose ) {
				cout << "The operations used are:" << endl;
				PrintOperationSet(cout, opslist);
			}
			PrintOperationSet(evalListF, opslist);
			evalListF.close();
			return 0;
		}

		// apply the estimates and determine how long the circuit's outputs should take to evaluate
		if( evaluation_run_mode ) {
			vector<CircuitSimulation> opslist;
			driver.graph.GenerateOperationList(opslist);
			driver.graph.UpdateRuntimeEstimates(opslist, timings);
			driver.graph.PrintRuntimeEstimates(cout);
		}

		PalisadeCircuit<ILDCRT2n>	cir(cc, driver.graph);

		if( verbose )
			cir.CircuitDump();

		auto intypes = cir.GetGraph().GetInputTypes();
		if( verbose ) {
			cout << "Circuit takes " << intypes.size() << " inputs:" <<endl;
			for( size_t i = 0; i < intypes.size(); i++ ) {
				cout << "input " << i << ": type " << intypes[i] << endl;
			}
		}

		size_t curVec = 0, maxVec = MAXVECS; //sizeof(vecs)/sizeof(vecs[0]);
		size_t curInt = 0, maxInt = sizeof(ints)/sizeof(ints[0]);

		for( size_t i = 0; i < intypes.size(); i++ ) {

			switch(intypes[i]) {
			case INT:
				if( curInt == maxInt )
					throw std::logic_error("out of ints");
				inputs[i] = intVecs[curInt++][0];
				break;

			case VECTOR_INT:
				if( curVec == maxVec )
					throw std::logic_error("out of vecs");
				inputs[i] = cipherVecs[curVec++][0];
				break;

			case MATRIX_RAT:
				inputs[i] = emat;
				break;

			default:
				throw std::logic_error("type not supported");
			}
		}

		vector<TimingInfo>	times;
		cc.StartTiming(&times);

		CircuitIO<ILDCRT2n> outputs = cir.CircuitEval(inputs, verbose);

		cc.StopTiming();

		if( verbose )
			CircuitNodeWithValue<ILDCRT2n>::PrintLog(cout);

		// apply the actual timings to the circuit
		for( auto& node : cir.GetGraph().getAllNodes() ) {
			int s = node.second->GetEvalSequenceNumber();
			if( s < 0 ) continue;
			node.second->SetRuntime( times[s].timeval );
		}

		// print the output
		for( auto& out : outputs ) {
			IntPlaintextEncoding result;

			cout << "For output " << out.first << endl;
			cc.Decrypt(kp.secretKey, {out.second.GetIntVecValue()}, &result);

			size_t i;
			const size_t n = 10;
			for( i=0; i < n; i++ )
				cout << result[i] << " ";
			cout << (( i == n ) ? "..." : " ") << endl;
		}

		if( print_result_graph ) {
			cir.GetGraph().DisplayDecryptedGraph(resultGraph, cc, kp.secretKey);
			if( resultGF.is_open() )
				resultGF.close();
		}

		// we have the times for each node, now sum up for each output
		for( auto& out : cir.GetGraph().getOutputs() ) {
			CircuitNodeWithValue<ILDCRT2n> *n = cir.GetGraph().getNodeById(out);
			cir.GetGraph().ClearVisited();
			n->CircuitVisit(cir.GetGraph());
			cout << "RUNTIME ACTUAL FOR Output " << out << " " << cir.GetGraph().GetRuntime() << endl;
		}

		if( verbose ) {
			cout << "Timing Information:" << endl;
			for( size_t i = 0; i < times.size(); i++ ) {
				cout << times[i] << endl;
			}
		}

		break;
	}

	return 0;
}

