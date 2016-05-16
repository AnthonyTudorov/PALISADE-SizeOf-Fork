#include "sheoperations.h"

namespace lbcrypto {

	template <class Element>
	Ciphertext<Element> SHEFeatures<Element>::KeySwitch(const LPPrivateKey<Element> &newPrivateKey, const LPPrivateKey<Element> &origPrivateKey, const DiscreteGaussianGenerator &dgg,
		const Ciphertext<Element> &origCipherText) const {

		Element keySwitchHint(KeySwitchHintGen(newPrivateKey, origPrivateKey, dgg));

		const LPCryptoParameters<Element> &cryptoParamsOriginal = origPrivateKey.GetAbstractCryptoParameters();

		const ElemParams &originalKeyParams = cryptoParamsOriginal.GetElementParams();

		Element ciphertextElement(originalKeyParams);

		ciphertextElement = origCipherText.GetElement();

		ciphertextElement = keySwitchHint * ciphertextElement;

		Ciphertext<Element> newCipherText(origCipherText);

		newCipherText.SetElement(ciphertextElement);

		return newCipherText;
	}




}//END OF NAMESPACE LPCRYPTO
