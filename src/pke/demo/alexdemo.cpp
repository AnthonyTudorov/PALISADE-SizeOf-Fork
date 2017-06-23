/*
 * alexdemo.cpp
 *
 *  Created on: Jun 22, 2017
 *      Author: gerardryan
 */


//  plaintext = rand(1:10, 2)
//  ctx = Fhe.keygen(scheme)
//  write("pk", ctx, Fhe.KEY_TYPE_PUBLIC)
//  write("sk", ctx, Fhe.KEY_TYPE_SECRET)
//  pk = read("pk", Fhe.KEY_TYPE_PUBLIC)
//  sk = read("sk", Fhe.KEY_TYPE_SECRET)
//  cs = Fhe.encrypt(pk, plaintext)
//  @test_broken Fhe.decrypt(sk, cs) == plaintext
//  @test_broken Fhe.decrypt(ctx, cs) == plaintext

#include "palisade.h"
#include "encoding/intplaintextencoding.h"
#include "cryptocontextgen.h"
using namespace lbcrypto;

int
main()
{
	IntPlaintextEncoding	ptxt = { 3, 1, 4, 1, 5, 9, 2, 6 };
	CryptoContext<ILVector2n> cc = GenCryptoContextElementLTV(16,32);

	// ENCRYPT/DECRYPT
	LPKeyPair<ILVector2n> kp = cc.KeyGen();
	auto ct = cc.Encrypt(kp.publicKey, ptxt);
	IntPlaintextEncoding	newPtxt;
	cc.Decrypt(kp.secretKey, ct, &newPtxt);

	newPtxt.resize( ptxt.size() );

	if( ptxt != newPtxt )
		std::cout << "Mismatch #1" << std::endl;

	// SERIALIZE AND SAVE
	Serialized serPublic, serPrivate;

	kp.publicKey->Serialize(&serPublic);
	SerializableHelper::WriteSerializationToFile(serPublic, "pub.ser");

	kp.secretKey->Serialize(&serPrivate);
	SerializableHelper::WriteSerializationToFile(serPrivate, "priv.ser");

	// LOAD the saved serialization and get a context out of it
	Serialized newSerPub;
	SerializableHelper::ReadSerializationFromFile("pub.ser", &newSerPub);
	Serialized newSerPri;
	SerializableHelper::ReadSerializationFromFile("priv.ser", &newSerPri);

	CryptoContext<ILVector2n> newcc = CryptoContextFactory<ILVector2n>::DeserializeAndCreateContext(newSerPub);
	newcc.Enable(ENCRYPTION);

	LPKeyPair<ILVector2n> newkp;

	newkp.publicKey = newcc.deserializePublicKey(newSerPub);
	newkp.secretKey = newcc.deserializeSecretKey(newSerPri);
	auto ct2 = newcc.Encrypt(newkp.publicKey, ptxt);
	IntPlaintextEncoding	newPtxt2;
	newcc.Decrypt(newkp.secretKey, ct2, &newPtxt2);

	newPtxt2.resize( ptxt.size() );

	if( ptxt != newPtxt2 )
		std::cout << "Mismatch #2" << std::endl;
}
