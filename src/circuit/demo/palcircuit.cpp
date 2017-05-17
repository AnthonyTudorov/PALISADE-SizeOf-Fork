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

int
main(int argc, char *argv[])
{
	CryptoContext<ILVector2n> cc = GenCryptoContextElementNull(8, 8);

	PalisadeCircuit	cir(cc);

	IntPlaintextEncoding pt1 = { 1,2,3,5 };
	IntPlaintextEncoding pt2 = { 1,2,3,7 };

	LPKeyPair<ILVector2n> kp = cc.KeyGen();

	vector<shared_ptr<Ciphertext<ILVector2n>>> ct1 = cc.Encrypt(kp.publicKey,pt1);
	vector<shared_ptr<Ciphertext<ILVector2n>>> ct2 = cc.Encrypt(kp.publicKey,pt2);

	CircuitIO inputs = { {0,ct1[0]}, {1,ct2[0]} };

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

		std::cout << "input 0 is " << pt1 << std::endl;
		std::cout << "input 1 is " << pt2 << std::endl;

		CircuitIO outputs = cir.CircuitEval(driver.graph, inputs);

		for( auto& out : outputs ) {
			IntPlaintextEncoding result;

			std::cout << "For output " << out.first << std::endl;
			cc.Decrypt(kp.secretKey, {out.second}, &result);

			std::cout << result << std::endl;
		}
	}

	return 0;
}

