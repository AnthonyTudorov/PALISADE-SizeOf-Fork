#ifndef LIB_ENCODING_CRYPTOUTILITY
#define LIB_ENCODING_CRYPTOUTILITY

namespace lbcrypto {

template<typename Element>
class CryptoUtility {
public:

	static EncryptResult Encrypt(
		const LPPublicKeyEncryptionScheme<Element>& scheme,
		const LPPublicKey<Element>& publicKey,
	        const PlaintextEncodingInterface& plaintext,
		Ciphertext<Element> *ciphertext) {
			if(scheme.IsEnabled(ENCRYPTION)) {
				Element pt(publicKey.GetCryptoParameters().GetElementParams());
				plaintext.Encode(publicKey.GetCryptoParameters().GetPlaintextModulus(), &pt);
				pt.SwitchFormat();

				return scheme.getAlgorithm().Encrypt(publicKey,pt,ciphertext);
			}
			else {
				throw std::logic_error("This operation is not supported");
			}
	}

};

}

#endif
