#ifndef LBCRYPTO_SHE_OPERATION_H
#define LBCRYPTO_SHE_OPERATION_H


#include "pubkeylp.h"
#include "../math/discretegaussiangenerator.h"
#include "ciphertext.h"

namespace lbcrypto{

	template <class Element>
	class SHELTVFeatures{


		/*
		Key switch operation changes the cipher text generated indirectly under a private key to a cipher text under the new private key.
		Input parameters are the new private key, old private key and the cipher text generated under the old private key.
		Output parameter is the new cipher text generated under the new private key, preserving the plain text.
		*/
		Ciphertext<Element> KeySwitch(const LPPrivateKey<Element> &newPrivateKey, const LPPrivateKey<Element> &origPrivateKey, const DiscreteGaussianGenerator &dgg,
		const Ciphertext<Element> &origCipherText) const;


		LPKeySwitchHint KeySwitchHintGen(const LPPrivateKey<Element> &newPrivateKey,
			const LPPrivateKey<Element> &origPrivateKey,
			DiscreteGaussianGenerator &dgg) const;

		CipherTextSparseKey<Element> RingReduce(Ciphertext<Element> &origCipherText,
			LPPrivateKeyLWENTRU<Element> &origPrivateKey,
			DiscreteGaussianGenerator &dgg) const;

		/*
		void RingReduce(Ciphertext<Element> &CipherText,
			LPPrivateKeyLWENTRU<Element> &PrivateKey,
			const DiscreteGaussianGenerator &dgg) const;
		*/


		void ModReduce(Ciphertext<Element> &ciphertext, LPPrivateKey<Element> &sk);







	};

}


#endif
