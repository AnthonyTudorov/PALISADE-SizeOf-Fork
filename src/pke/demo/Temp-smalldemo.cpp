/*
 * Temp-smalldemo.cpp
 *
 *  Created on: Jan 4, 2018
 *      Author: gerardryan
 */

#include "palisade.h"
#include "cryptocontext.h"
#include "utils/serial.h"

extern template class lbcrypto::LPCryptoParametersNull<lbcrypto::Poly>;
extern template class lbcrypto::LPCryptoParametersNull<lbcrypto::NativePoly>;

extern template class lbcrypto::LPPublicKeyEncryptionSchemeNull<lbcrypto::Poly>;
extern template class lbcrypto::LPPublicKeyEncryptionSchemeNull<lbcrypto::NativePoly>;

extern template class lbcrypto::LPAlgorithmNull<lbcrypto::Poly>;
extern template class lbcrypto::LPAlgorithmNull<lbcrypto::NativePoly>;

extern template class lbcrypto::LPAlgorithmParamsGenNull<lbcrypto::Poly>;
extern template class lbcrypto::LPAlgorithmParamsGenNull<lbcrypto::NativePoly>;

extern template class lbcrypto::LPAlgorithmSHENull<lbcrypto::Poly>;
extern template class lbcrypto::LPAlgorithmSHENull<lbcrypto::NativePoly>;

extern template class lbcrypto::LPLeveledSHEAlgorithmNull<lbcrypto::Poly>;
extern template class lbcrypto::LPLeveledSHEAlgorithmNull<lbcrypto::NativePoly>;


extern template class lbcrypto::LPCryptoParametersNull<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPPublicKeyEncryptionSchemeNull<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPAlgorithmNull<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPAlgorithmParamsGenNull<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPAlgorithmSHENull<lbcrypto::DCRTPoly>;
extern template class lbcrypto::LPLeveledSHEAlgorithmNull<lbcrypto::DCRTPoly>;

using namespace lbcrypto;

CEREAL_REGISTER_TYPE(LPCryptoParametersNull<Poly>);
CEREAL_REGISTER_TYPE(LPCryptoParametersNull<NativePoly>);
CEREAL_REGISTER_TYPE(LPCryptoParametersNull<DCRTPoly>);

int
main()
{
	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextNull(8,256);
	cc->Enable(ENCRYPTION | SHE );

	if( true ) {
		auto kp = cc->KeyGen();

		int inputs[] = { 1, 2, 3, 4 };
		Plaintext ptxt[4];
		Ciphertext<Poly> ctxt[4];

		for( int i=0; i<4; i++ ) {
			ptxt[i] = cc->MakeIntegerPlaintext( inputs[i] );
			cout << inputs[i] << " " << ptxt[i]->GetElement<Poly>() << endl;
			ctxt[i] = cc->Encrypt(kp.publicKey, ptxt[i]);
		}

//		stringstream ss;
//		Serial::Serialize(ctxt[0],ss);

		auto d1 = ctxt[0] - ctxt[1];
		auto d2 = ctxt[2] - ctxt[3];

		cout << "d1 " << d1 << endl;
		cout << "d2 " << d2 << endl;

		Plaintext p1, p2;
		cc->Decrypt(kp.secretKey, d1, &p1);
		cc->Decrypt(kp.secretKey, d2, &p2);

		cout << p1 << endl;
		cout << p2 << endl;
	}
	return 0;
}


