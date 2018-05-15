/*
 * Temp-smalldemo.cpp
 *
 *  Created on: Jan 4, 2018
 *      Author: gerardryan
 */

#include "palisade.h"
#include "cryptocontext.h"
using namespace lbcrypto;

int
main()
{
	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(8,256);
	cc->Enable(ENCRYPTION | SHE );
	auto kp = cc->KeyGen();

	int inputs[] = { 1, 2, 3, 4 };
	Plaintext ptxt[4];
	Ciphertext<Poly> ctxt[4];

	for( int i=0; i<4; i++ ) {
		ptxt[i] = cc->MakeIntegerPlaintext( inputs[i] );
		cout << inputs[i] << " " << ptxt[i]->GetElement<Poly>() << endl;
		ctxt[i] = cc->Encrypt(kp.publicKey, ptxt[i]);
	}

	auto d1 = ctxt[0] - ctxt[1];
	auto d2 = ctxt[2] - ctxt[3];

	cout << "d1 " << d1 << endl;
	cout << "d2 " << d2 << endl;

	Plaintext p1, p2;
	cc->Decrypt(kp.secretKey, d1, &p1);
	cc->Decrypt(kp.secretKey, d2, &p2);

	cout << p1 << endl;
	cout << p2 << endl;
	return 0;
}


