#ifndef LIB_ENCODING_CRYPTOUTILITY
#define LIB_ENCODING_CRYPTOUTILITY

#include <iostream>
#include "../encoding/plaintext.h"
#include "../encoding/byteplaintextencoding.h"
#include "../utils/serializablehelper.h"

namespace lbcrypto {

template<typename Element>
class CryptoUtility {
public:

	/**
	* perform KeySwitch on a vector of ciphertext
	* @param scheme - a reference to the encryption scheme in use
	* @param keySwitchHint - reference to KeySwitchHint
	* @param ciphertext - vector of ciphertext
	* @param newCiphertext - contains a vector of KeySwitched ciphertext
	*/
	static void KeySwitch(
		const LPPublicKeyEncryptionScheme<Element>& scheme,
		const LPEvalKeyNTRU<Element> &keySwitchHint,
		const vector<shared_ptr<Ciphertext<Element>>>& ciphertext,
		vector<shared_ptr<Ciphertext<Element>>> *newCiphertext)
	{
		for (int i = 0; i < ciphertext.size(); i++) {
			newCiphertext->push_back( scheme.KeySwitch(keySwitchHint, *ciphertext.at(i)) );
		}
	}

	/**
	* perform ModReduce on a vector of ciphertext
	* @param scheme - a reference to the encryption scheme in use
	* @param ciphertext - vector of ciphertext
	*/
	static void ModReduce(
		const LPPublicKeyEncryptionScheme<Element>& scheme,
		vector<shared_ptr<Ciphertext<Element>>> *ciphertext)
	{
		for (int i = 0; i < ciphertext->size(); i++) {
			scheme.ModReduce(&ciphertext->at(i));
		}
	}

	/**
	* perform RingReduce on a vector of ciphertext
	* @param &scheme - a reference to the encryption scheme in use
	* @param ciphertext - vector of ciphertext
	* @param &keySwitchHint - is the keySwitchHint from original private key to sparse private key
	*/
	//void RingReduce(Ciphertext<Element> *cipherText, const LPEvalKeyNTRU<Element> &keySwitchHint) const
	static void RingReduce(
		const LPPublicKeyEncryptionScheme<Element>& scheme,
		vector<shared_ptr<Ciphertext<Element>>> *ciphertext,
		const LPEvalKeyNTRU<Element> &keySwitchHint)

	{
		for (int i = 0; i < ciphertext->size(); i++) {
			scheme.RingReduce(&(*ciphertext->at(i)), keySwitchHint);
		}
	}

	/**
	* perform RingReduce on a vector of ciphertext
	* @param &scheme - a reference to the encryption scheme in use
	* @param ciphertext1 - first cipher text
	* @param ciphertext2 - second cipher text
	* @param &quadKeySwitchHint - is the quadratic key switch hint from original private key to the quadratic key
	* @param ciphertextResult - resulting ciphertext
	*/
	static void ComposedEvalMult(
		const LPPublicKeyEncryptionScheme<Element>& scheme,
		const vector<Ciphertext<Element>> &ciphertext1,
		const vector<Ciphertext<Element>> &ciphertext2,
		const LPEvalKeyNTRU<Element> &quadKeySwitchHint, 
		vector<shared_ptr<Ciphertext<Element>>> *ciphertextResult
		)
	{
		if (ciphertext1.size() != ciphertext2.size()) {
			throw std::logic_error("Cannot have ciphertext of different length");
		}
		for (int i = 0; i < ciphertext1.size(); i++) {
			scheme.ComposedEvalMult(ciphertext1.at(i), ciphertext2.at(i), quadKeySwitchHint, ciphertextResult->at(i));
		}
	}

};

}

#endif
