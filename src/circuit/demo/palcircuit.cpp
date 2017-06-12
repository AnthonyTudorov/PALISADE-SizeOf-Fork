/*
 * palcircuit.cpp
 *
 *  Created on: Apr 7, 2017
 *      Author: gerardryan
 */

#include "palisade.h"
#include "cryptocontextgen.h"
#include "parsedriver.h"
#include "palisadecircuit.h"
using namespace lbcrypto;
using std::cout;

void usage() {
	cout << "Arguments are" << endl;
	cout << "-d  --  debug mode on the parse" << endl;
	cout << "-p  --  print the circuit in DOT format for use with graphviz" << endl;
	cout << "-v  --  verbose details about the circuit" << endl;
	cout << "-h  --  this message" << endl;
}

int
main(int argc, char *argv[])
{
	CryptoContext<ILDCRT2n> cc = GenCryptoContextElementArrayNull(8, 5, 8, 10);
	cc.Enable(LEVELEDSHE);

	PalisadeCircuit	cir(cc);

	IntPlaintextEncoding vecs[] = {
			{ 1,2,3,5 },
			{ 1,2,3,7 }
	};
	IntPlaintextEncoding ints[] = { { 7 }, { 3 } };

	LPKeyPair<ILDCRT2n> kp = cc.KeyGen();
	cc.EvalMultKeyGen(kp.secretKey);

	vector< vector<shared_ptr<Ciphertext<ILDCRT2n>>> > cipherVecs;
	for( size_t i = 0; i < sizeof(vecs)/sizeof(vecs[0]); i++ )
		cipherVecs.push_back( cc.Encrypt(kp.publicKey, vecs[i]) );

	vector< vector<shared_ptr<Ciphertext<ILDCRT2n>>> > intVecs;
	for( size_t i = 0; i < sizeof(ints)/sizeof(ints[0]); i++ )
		intVecs.push_back( cc.Encrypt(kp.publicKey, ints[i]) );

	CircuitIO inputs;

	bool debug_parse = false;
	bool print_graph = false;
	bool verbose = false;
	for( int i=1; i<argc; i++ ) {
		string arg(argv[i]);
		if( arg == "-d" ) {
			debug_parse = true;
			continue;
		}
		if( arg == "-p" ) {
			print_graph = true;
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
		if( arg[0] == '-' ) { // an unrecognized arg
			usage();
			return 0;
		}

		if( verbose )
			cout << "Crypto Parameters used:" << endl << *cc.GetCryptoParameters() << endl;


		pdriver driver(debug_parse);

		auto res = driver.parse(argv[i]);
		if( res != 0 ) {
			cout << "Parse error" << endl;
			return 1;
		}

		if( verbose ) {
			cout << "Circuit parsed" << endl;
		}

		if( print_graph )
			driver.graph.DisplayGraph();

		if( verbose )
			cir.CircuitDump(driver.graph);

		cir.CircuitSetup(driver.graph, verbose);
		if( print_graph )
			driver.graph.DisplayGraph();

		if( verbose )
			cir.CircuitDump(driver.graph);

		auto intypes = driver.graph.GetInputTypes();
		if( verbose ) {
			cout << "Circuit takes " << intypes.size() << " inputs:" <<endl;
			for( size_t i = 0; i < intypes.size(); i++ ) {
				cout << "input " << i << ": type " << intypes[i] << endl;
			}
		}

		//
		size_t curVec = 0, maxVec = sizeof(vecs)/sizeof(vecs[0]);
		size_t curInt = 0, maxInt = sizeof(ints)/sizeof(ints[0]);

		for( size_t i = 0; i < intypes.size(); i++ ) {
			if( verbose ) cout << "input " << i << ": value ";

			switch(intypes[i]) {
			case INT:
				if( curInt == maxInt )
					throw std::logic_error("out of ints");
				inputs[i] = intVecs[curInt++][0];
				if( verbose ) cout << ints[i] << endl;
				break;

			case VECTOR_INT:
				if( curVec == maxVec )
					throw std::logic_error("out of vecs");
				inputs[i] = cipherVecs[curVec++][0];
				if( verbose ) cout << vecs[i] << endl;
				break;

			default:
				throw std::logic_error("type not supported");
			}
		}

		CircuitNode::ResetSimulation();

		CircuitIO outputs = cir.CircuitEval(driver.graph, inputs, verbose);

		CircuitNode::PrintLog(cout);

		for( auto& out : outputs ) {
			IntPlaintextEncoding result;

			if( verbose ) cout << "For output " << out.first << endl;
			cc.Decrypt(kp.secretKey, {out.second.GetIntVecValue()}, &result);

			if( verbose ) cout << result << endl;
		}

		if( print_graph ) {
			driver.graph.DisplayDecryptedGraph(cc, kp.secretKey);
		}
	}

	return 0;
}

