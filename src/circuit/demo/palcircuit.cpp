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

int
main(int argc, char *argv[])
{
	CryptoContext<ILVector2n> cc = GenCryptoContextElementNull(8, 8);

	std::cout << *cc.GetCryptoParameters() << std::endl;

	PalisadeCircuit	cir(cc);

	IntPlaintextEncoding vecs[] = {
			{ 1,2,3,5 },
			{ 1,2,3,7 }
	};
	IntPlaintextEncoding ints[] = { { 7 }, { 3 } };

	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector< vector<shared_ptr<Ciphertext<ILVector2n>>> > cipherVecs;
	for( size_t i = 0; i < sizeof(vecs)/sizeof(vecs[0]); i++ )
		cipherVecs.push_back( cc.Encrypt(kp.publicKey, vecs[i]) );

	vector< vector<shared_ptr<Ciphertext<ILVector2n>>> > intVecs;
	for( size_t i = 0; i < sizeof(ints)/sizeof(ints[0]); i++ )
		intVecs.push_back( cc.Encrypt(kp.publicKey, ints[i]) );

	CircuitIO inputs;

	bool verbose = false;
	for( int i=1; i<argc; i++ ) {
		if( string(argv[i]) == "-v" ) {
			verbose = true;
			continue;
		}

		pdriver driver(verbose);

		auto res = driver.parse(argv[i]);
		if( res != 0 ) {
			std::cout << "Parse error" << std::endl;
			return 1;
		}

		std::cout << "Begin DOT output" << std::endl;
		driver.graph.DisplayGraph();
		std::cout << "End DOT output" << std::endl;

		auto intypes = driver.graph.GetInputTypes();

		size_t curVec = 0, maxVec = sizeof(vecs)/sizeof(vecs[0]);
		size_t curInt = 0, maxInt = sizeof(ints)/sizeof(ints[0]);
		cout << "Circuit takes " << intypes.size() << " inputs:" <<endl;
		for( size_t i = 0; i < intypes.size(); i++ ) {
			cout << "input " << i << ": type " << intypes[i] << ", value is: ";

			switch(intypes[i]) {
			case INT:
				if( curInt == maxInt )
					throw std::logic_error("out of ints");
				inputs[i] = intVecs[curInt++][0];
				cout << ints[i] << endl;
				break;

			case VECTOR_INT:
				if( curVec == maxVec )
					throw std::logic_error("out of vecs");
				inputs[i] = cipherVecs[curVec++][0];
				cout << vecs[i] << endl;
				break;

			default:
				throw std::logic_error("type not supported");
			}
		}
		cout << endl;

		CircuitIO outputs = cir.CircuitEval(driver.graph, inputs);

		for( auto& out : outputs ) {
			IntPlaintextEncoding result;

			std::cout << "For output " << out.first << std::endl;
			cc.Decrypt(kp.secretKey, {out.second.GetIntVecValue()}, &result);

			std::cout << result << std::endl;
		}

		std::cout << "Begin DOT output" << std::endl;
		driver.graph.DisplayGraph();
		std::cout << "End DOT output" << std::endl;
	}

	return 0;
}

