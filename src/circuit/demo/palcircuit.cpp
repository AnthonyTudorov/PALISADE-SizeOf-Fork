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

void usage() {
	cout << "Usage is palcircuit {Arguments} inputfile specfile" << endl;
	cout << "Arguments are" << endl;
	cout << "-d  --  debug mode on the parse" << endl;
	cout << "-ginput[=file]  --  print a graph of the input circuit, DOT format" << endl;
	cout << "-gproc[=file]  --  print a graph of the preprocessed input circuit, DOT format" << endl;
	cout << "-gresult[=file]  --  print a graph of the result of executing the circuit, DOT format" << endl;
	cout << "-econtext[=file] -- export a serialization of the context to file" << endl;
	cout << "-elist=filename  --  save information needed for estimating in file filename; stop after generating" << endl;
	cout << "-estats=filename  --  use this information for estimating runtime" << endl;
	cout << "-v  --  verbose details about the circuit" << endl;
	cout << "-null  --  use the null scheme" << endl;
	cout << "-printall  --  prints value of every node after evaluation" << endl;
	cout << "-otrace -- verbose details about the operations" << endl;
	cout << "-ap -- generate application profile and stop" << endl;
	cout << "-h  --  this message" << endl;
}

Plaintext EncodeFunction(CryptoContext<DCRTPoly> cc, int64_t val) {
	return cc->MakePackedPlaintext({(uint64_t)val});
}

int
main(int argc, char *argv[])
{
	const PlaintextModulus ptm = 1073872897;

	bool debug_parse = false;
	bool print_input_graph = false;
	bool print_preproc_graph = false;
	bool print_result_graph = false;
	bool verbose = false;
	bool evaluation_list_mode = false;
	bool evaluation_run_mode = false;
	bool print_all_flag = false;
	bool print_context_flag = false;
	bool use_null = false;
	bool gen_app_profile = false;

	ofstream contextF;
	ostream *ctxStr = &cout;

	ofstream evalListF;
	ostream *elistStr = &cout;

	ifstream evalStatF;

	ofstream inGF, procGF, resultGF;
	ostream	*inGraph = &cout;
	ostream	*procGraph = &cout;
	ostream	*resultGraph = &cout;

	string inputfile;
	string specfile;

	// PROCESS USER ARGS
	for( int i=1; i<argc; i++ ) {
		string arg(argv[i]);
		string argf(arg);

		// split by = sign
		auto epos = arg.find('=');
		if( epos == string::npos )
			argf.clear();
		else {
			arg = arg.substr(0, epos);
			argf = argf.substr(epos+1);
		}

		if( arg == "-d" ) {
			debug_parse = true;
		}
		else if( arg == "-ap" ) {
			gen_app_profile = true;
		}
		else if( arg == "-otrace" ){
			lbcrypto::CircuitOpTrace = true;
		}
		else if( arg == "-null" ){
			use_null = true;
		}
		else if( arg == "-ginput" ) {
			print_input_graph = true;
			if( argf.size() > 0 ) {
				inGF.open(argf, ostream::out);
				if( !inGF.is_open() ) {
					cout << "Unable to open file " << argf << endl;
					return 1;
				}
				inGraph = &inGF;
			}
		}
		else if( arg == "-gproc" ) {
			print_preproc_graph = true;
			if( argf.size() > 0 ) {
				procGF.open(argf, ostream::out);
				if( !procGF.is_open() ) {
					cout << "Unable to open file " << argf << endl;
					return 1;
				}
				procGraph = &procGF;
			}
		}
		else if( arg == "-gresult" ) {
			print_result_graph = true;
			if( argf.size() > 0 ) {
				resultGF.open(argf, ostream::out);
				if( !resultGF.is_open() ) {
					cout << "Unable to open file " << argf << endl;
					return 1;
				}
				resultGraph = &resultGF;
			}
		}
		else if( arg == "-v" ) {
			verbose = true;
		}
		else if( arg == "-printall" ) {
			print_all_flag = true;
		}
		else if( arg == "-h" ) {
			usage();
			return 0;
		}
		else if( arg == "-econtext" ) {
			print_context_flag = true;
			if( argf.size() > 0 ) {
				contextF.open(argf, ostream::out);
				if( !contextF.is_open() ) {
					cout << "Unable to open file " << argf << endl;
					return 1;
				}
				ctxStr = &contextF;
			}
		}
		else if( arg == "-elist" ) {
			evaluation_list_mode = true;
			if( argf.size() > 0 ) {
				evalListF.open(argf, ofstream::out);
				if( !evalListF.is_open() ) {
					cout << "Unable to open file " << argf << endl;
					return 1;
				}
				elistStr = &evalListF;
			}
		}
		else if( arg == "-estats" ) {
			evaluation_run_mode = true;
			evalStatF.open(argf, ofstream::in);
			if( !evalStatF.is_open() ) {
				cout << "Unable to open file " << argf << endl;
				return 1;
			}
		}
		else if( arg[0] == '-' ) { // an unrecognized flag
			usage();
			return 1;
		}
		else {
			inputfile = arg;
			if( argc != i+2 ) {
				usage();
				return 1;
			}
			specfile = argv[i+1];
			break;
		}
	}

	if( inputfile.length() == 0 ) {
		usage();
		return 1;
	}

	if( evaluation_list_mode && evaluation_run_mode ) {
		cout << "Cannot specify both -elist and -estats" << endl;
		return 1;
	}

	// Prepare to process the graph

	EncodingParams ep( new EncodingParamsImpl(ptm) );

	CryptoContext<DCRTPoly> cc = use_null ?
			CryptoContextFactory<DCRTPoly>::genCryptoContextNull(32, ep) :
			CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(ep,1.004,3.19,0,4,0,OPTIMIZED,2,30);

	if( verbose ) {
		std::cout << "\np = " << cc->GetCryptoParameters()->GetPlaintextModulus() << std::endl;
		std::cout << "n = " << cc->GetRingDimension() << std::endl;
		std::cout << "log2 q = " << log2(cc->GetCryptoParameters()->GetElementParams()->GetModulus().ConvertToDouble()) << std::endl;
	}

	cc->Enable(ENCRYPTION);
	try {
	cc->Enable(SHE);
	} catch(...) {}
	try {
		cc->Enable(LEVELEDSHE);
	} catch(...) {}

	const usint m = cc->GetCyclotomicOrder();
	PackedEncoding::SetParams(m, ep);
	ep->SetBatchSize(1024);

	// when in evaluation mode (prepare to estimate/run, then stop), save the CryptoContext
	if( print_context_flag ) {
		Serialized serObj;
		serObj.SetObject();
		if( cc->Serialize(&serObj) == false ) {
			cout << "Can't serialize CryptoContext" << endl;
			return 1;
		}
		SerializableHelper::SerializationToStream(serObj, *ctxStr);
	}

	// PARSE THE CIRCUIT
	pdriver driver(debug_parse);

	if( verbose ) {
		cout << "Parsing" << endl;
	}

	if( driver.parse(inputfile) != 0 ) {
		cout << "Error parsing input file " << inputfile << endl;
		return 1;
	}

	if( driver.parse(specfile) != 0 ) {
		cout << "Error parsing spec file " << specfile << endl;
		return 1;
	}

	if( verbose ) {
		cout << "Circuit parsed" << endl;
	}

	// From the parsed circuit, create a graph that can hold values
	PalisadeCircuit<DCRTPoly>	cir(cc, driver.graph, EncodeFunction);

	if( print_input_graph ) {
		cir.GetGraph().DisplayGraph(*inGraph);
		if( inGF.is_open() )
			inGF.close();
	}

	// ASSIGN DEPTHS (and, eventually, optimize)
	if( verbose ) cout << "Preprocessing" << endl;
	cir.GetGraph().Preprocess();

	if( verbose )
		cout << "Maximum depth is " << cir.GetGraph().GetMaximumDepth() << endl;

	if( print_preproc_graph ) {
		cir.GetGraph().DisplayGraph(*procGraph);
		if( procGF.is_open() )
			procGF.close();
	}

	auto quot = [] (string s) { return "\"" + s + "\""; };
	if( gen_app_profile ) {
		cout << quot( "confset" ) << ": {"
				<< quot("type") << ":" << quot("MQgen") << ","
				<< quot("secLevel") << ":" << quot("1.004") << ","
				<< quot("numAdds") << ":" << quot("0") << ","
				<< quot("numMults") << ": \"" << cir.GetGraph().GetMaximumDepth() << "\","
				<< quot("numKS") << ":" << quot("0") << ","
				<< quot("p") << ":" << quot("8192") << ","
				<< quot("relinWindow") << ":" << quot("30") << ","
				<< quot("dist") << ":" << quot("3.19") << ","
				<< quot("qbits") << ":" << quot("60") << "}";
		return 0;
	}


	// to do estimates we need to know what functions we called; write them out and finish up
	if( evaluation_list_mode ) {
		cir.GenerateOperationList();
		cir.GetGraph().PrintOperationSet(*elistStr, verbose);
		evalListF.close();
		return 0;
	}

	// when generating timing estimates, need to read in the Context and the timings
	TimingStatisticsMap timings;
	if( evaluation_run_mode ) {
		Serialized serObj;
		if( SerializableHelper::StreamToSerialization(evalStatF, &serObj) == false ) {
			cout << "Input file does not begin with a serialization" << endl;
			return 1;
		}

		// FIXME check for match
		//		if( (cc = CryptoContextFactory<DCRTPoly>::DeserializeAndCreateContext(serObj)) == NULL ) {
		//			cout << "Unable to deserialize and initialize from saved crypto context" << endl;
		//			evalStatF.close();
		//			return 1;
		//		}

		do {
			serObj.SetObject();
			if( SerializableHelper::StreamToSerialization(evalStatF, &serObj) == false )
				break;
			TimingStatistics s;
			s.Deserialize(serObj);
			timings[TimingStatisticsKey(s.operation,s.argcnt)] = s;
		} while( true );

		evalStatF.close();

		if( verbose ) {
			cout << endl;
			for( const auto& t : timings )
				cout << t.second << endl;
			cout << endl;
		}

		// to calculate a runtime estimate, apply the estimates and determine how long the circuit's outputs should take to evaluate
		cir.GenerateOperationList();

		if( verbose ) {
			map<usint,map<TimingStatisticsKey,int>>& opsmap = CircuitNodeWithValue<DCRTPoly>::GetOperationsMap();
			for( auto& opentry : opsmap ) {
				cout << "node " << opentry.first << ":" << endl;

				for( auto& nodeops : opentry.second ) {
					cout << "   " << nodeops.first << " * " << nodeops.second << endl;
				}
			}
		}

		cir.ApplyRuntimeEstimates(timings);
		if( verbose )
			for( auto n : cir.GetGraph().getAllNodes() ) {
				cout << "Node " << n.first;
				cout << " node est " << n.second->GetRuntimeEstimateNode();
				cout << " node cum " << n.second->GetRuntimeEstimate() << endl;
			}
	}

	vector<int32_t> indexList = {-1, -2, -3, -4, -5, -6, -7, -8, -9, -10};

	LPKeyPair<DCRTPoly> kp = cc->KeyGen();
	cc->EvalMultKeyGen(kp.secretKey);
	cc->EvalSumKeyGen(kp.secretKey);
	cc->EvalAtIndexKeyGen(kp.secretKey, indexList);

	CircuitInput<DCRTPoly> inputs;

	auto inwires = cir.GetGraph().getInputs();
	if( verbose ) {
		cout << "Circuit takes " << inwires.size() << " inputs:" <<endl;
	}
	bool input_mapping_error = false;

	for( auto wire : inwires ) {
		auto type = cir.GetGraph().GetTypeForNode(wire);
		if( verbose )
			cout << "input " << wire << ": type " << type << endl;

		auto iv = driver.inputwires.find(wire);
		if( iv == driver.inputwires.end() ) {
			cout << "for wire " << wire << ", no input specified" << endl;
			input_mapping_error = true;
			continue;
		}

		if( iv->second.size() != 1 ) {
			cout << "for wire " << wire << ", currently only supports a single integer for input" << endl;
			input_mapping_error = true;
			continue;
		}

		Plaintext p = EncodeFunction(cc, iv->second[0]);

		switch(type) {
		case PLAINTEXT:
			inputs[wire] = p;
			break;

		case CIPHERTEXT:
		{
			auto ctxt = cc->Encrypt(kp.publicKey, p);
			inputs[wire] = ctxt;
		}
		break;

		//		case MATRIX_RAT:
		//			inputs[wire] = emat;
		//			break;

		default:
			throw std::logic_error("type not supported");
		}
	}

	if( input_mapping_error )
		return 1;

	vector<TimingInfo>	times;
	cc->StartTiming(&times);

	CircuitOutput<DCRTPoly> outputs = cir.CircuitEval(inputs, verbose);

	// postprocess the nodes
	for( auto& node : cir.GetGraph().getAllNodes() ) {
		if( node.second->IsOutput() || print_all_flag || print_result_graph )
			node.second->getValue().Decrypt(kp.secretKey);
	}

	if( print_all_flag ) {
		for( auto& node : cir.GetGraph().getAllNodes() ) {
			cout << "For node " << node.first << " Value: " << node.second->getValue() << " runtime " << node.second->GetRuntimeActual() << endl;
		}
	}

	// print the output
	for( auto& out : outputs ) {
		cout << "For output " << out.first << " type " << out.second.GetType() << " Value: " << out.second << endl;
	}

	if( print_result_graph ) {
		cir.GetGraph().DisplayGraph(*resultGraph);
		if( resultGF.is_open() )
			resultGF.close();
	}

	if( verbose ) {
		double totalEstimate = 0, totalActual = 0;
		for( auto& nod : cir.GetGraph().getAllNodes() ) {
			totalEstimate += nod.second->GetRuntimeEstimate();
			totalActual += nod.second->GetRuntimeActual();
			auto est = nod.second->GetRuntimeEstimate();
			auto act = nod.second->GetRuntimeActual();
			cout << "RUNTIME for " << nod.first << " " << act << endl;
			if( est != 0 )
				cout << "RUNTIME estimate for output " << nod.first << " " << est << endl;
		}
	}

	double totalEstimate = 0, totalActual = 0;
	for( auto& out : cir.GetGraph().getOutputs() ) {
		auto n = cir.GetGraph().getNodeById(out);
		totalEstimate += n->GetRuntimeEstimate();
		totalActual += n->GetRuntimeActual();
		auto est = n->GetRuntimeEstimate();
		auto act = n->GetRuntimeActual();
		cout << "RUNTIME for output " << out << " " << act << endl;
		if( est != 0 )
			cout << "RUNTIME estimate for output " << out << " " << est << endl;
	}

	// print time for each node's output and total time
	cout << "Total execution time " << totalActual << endl;
	if( totalEstimate != 0 )
		cout << "Total execution estimate " << totalEstimate << endl;

	if( verbose ) {
		cout << "Timing Information:" << endl;
		for( size_t i = 0; i < times.size(); i++ ) {
			cout << times[i] << endl;
		}
	}

	return 0;
}

