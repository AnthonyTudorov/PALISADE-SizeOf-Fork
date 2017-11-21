/**
 * @file bfvrns.h -- Operations for the RNS variant of the BFV cryptoscheme.
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology (NJIT)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
 /*
 *
 * This code implements a RNS variant of the Brakerski-Fan-Vercauteren (BFV) homomorphic encryption scheme.
 *
 * The BFV scheme is introduced in the following papers:
 *   - Zvika Brakerski (2012). Fully Homomorphic Encryption without Modulus Switching from Classical GapSVP. Cryptology ePrint Archive, Report 2012/078. (https://eprint.iacr.org/2012/078)
 *   - Junfeng Fan and Frederik Vercauteren (2012). Somewhat Practical Fully Homomorphic Encryption.  Cryptology ePrint Archive, Report 2012/144. (https://eprint.iacr.org/2012/144.pdf)
 *
 * Our implementation builds from the designs here:
 *   - Lepoint T., Naehrig M. (2014) A Comparison of the Homomorphic Encryption Schemes FV and YASHE. In: Pointcheval D., Vergnaud D. (eds) Progress in Cryptology – AFRICACRYPT 2014. AFRICACRYPT 2014. Lecture Notes in Computer Science, vol 8469. Springer, Cham. (https://eprint.iacr.org/2014/062.pdf)
 *	 - Jean-Claude Bajard and Julien Eynard and Anwar Hasan and Vincent Zucca (2016). A Full RNS Variant of FV like Somewhat Homomorphic Encryption Schemes. Cryptology ePrint Archive, Report 2016/510. (https://eprint.iacr.org/2016/510)
 */

#ifndef LBCRYPTO_CRYPTO_BFVRNS_H
#define LBCRYPTO_CRYPTO_BFVRNS_H

#include "palisade.h"

namespace lbcrypto {

	/**
 	* @brief This is the parameters class for the FV encryption scheme.
 	*
 	* The FV scheme parameter guidelines are introduced here:
 	*   - Junfeng Fan and Frederik Vercauteren. Somewhat Practical Fully Homomorphic Encryption.  Cryptology ePrint Archive, Report 2012/144. (https://eprint.iacr.org/2012/144.pdf)
 	*
 	* We used the optimized parameter selection from the designs here:
 	*   - Lepoint T., Naehrig M. (2014) A Comparison of the Homomorphic Encryption Schemes FV and YASHE. In: Pointcheval D., Vergnaud D. (eds) Progress in Cryptology – AFRICACRYPT 2014. AFRICACRYPT 2014. Lecture Notes in Computer Science, vol 8469. Springer, Cham. (https://eprint.iacr.org/2014/062.pdf)
 	*
 	* @tparam Element a ring element type.
 	*/
	template <class Element>
	class LPCryptoParametersBFVrns : public LPCryptoParametersRLWE<Element> {

		public:
			/**
			 * Default constructor.
			 */
			LPCryptoParametersBFVrns();

			/**
		 	 * Copy constructor.
	 		 * @param rhs - source
			 */
			LPCryptoParametersBFVrns(const LPCryptoParametersBFVrns &rhs);
			/**
			 * Constructor that initializes values.  Note that it is possible to set parameters in a way that is overall
			 * infeasible for actual use.  There are fewer degrees of freedom than parameters provided.  Typically one
			 * chooses the basic noise, assurance and security parameters as the typical community-accepted values, 
			 * then chooses the plaintext modulus and depth as needed.  The element parameters should then be choosen 
			 * to provide correctness and security.  In some cases we would need to operate over already 
			 * encrypted/provided ciphertext and the depth needs to be pre-computed for initial settings.
			 *
			 * @param &params Element parameters.  This will depend on the specific class of element being used.
			 * @param &plaintextModulus Plaintext modulus, typically denoted as p in most publications.
			 * @param distributionParameter Noise distribution parameter, typically denoted as /sigma in most publications.  Community standards typically call for a value of 3 to 6. Lower values provide more room for computation while larger values provide more security.
			 * @param assuranceMeasure Assurance level, typically denoted as w in most applications.  This is oftern perceived as a fudge factor in the literature, with a typical value of 9.
			 * @param securityLevel Security level as Root Hermite Factor.  We use the Root Hermite Factor representation of the security level to better conform with US ITAR and EAR export regulations.  This is typically represented as /delta in the literature.  Typically a Root Hermite Factor of 1.006 or less provides reasonable security for RLWE crypto schemes, although extra care is need for the LTV scheme because LTV makes an additional security assumption that make it suceptible to subfield lattice attacks.
			 * @param relinWindow The size of the relinearization window.  This is relevant when using this scheme for proxy re-encryption, and the value is denoted as r in the literature.
			 * @param mode optimization setting (RLWE vs OPTIMIZED)
			 * @param depth Depth is the depth of computation supported which is set to 1 by default.  Use the default setting unless you're using SHE, levelled SHE or FHE operations.
			 * @param maxDepth is the maximum homomorphic multiplication depth before performing relinearization
			 */
			LPCryptoParametersBFVrns(shared_ptr<typename Element::Params> params,
				const BigInteger &plaintextModulus, 
				float distributionParameter, 
				float assuranceMeasure, 
				float securityLevel, 
				usint relinWindow,
				MODE mode = RLWE,
				int depth = 1,
				int maxDepth = 2);

			/**
			* Constructor that initializes values.
			*
			* @param &params element parameters.
			* @param &encodingParams plaintext space parameters.
			* @param distributionParameter noise distribution parameter.
			* @param assuranceMeasure assurance level. = BigInteger::ZERO
			* @param securityLevel security level (root Hermite factor).
			* @param relinWindow the size of the relinearization window.
			* @param mode optimization setting (RLWE vs OPTIMIZED)
			* @param depth depth which is set to 1.
			* @param maxDepth is the maximum homomorphic multiplication depth before performing relinearization
			*/
			LPCryptoParametersBFVrns(shared_ptr<typename Element::Params> params,
				shared_ptr<EncodingParams> encodingParams,
				float distributionParameter,
				float assuranceMeasure,
				float securityLevel,
				usint relinWindow,
				MODE mode = RLWE,
				int depth = 1,
				int maxDepth = 2);

			/**
			* Destructor
			*/
			virtual ~LPCryptoParametersBFVrns() {}
			
			/**
			* Serialize the object
			* @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
			* @return true if successfully serialized
			*/
			bool Serialize(Serialized* serObj) const;

			/**
			* Populate the object from the deserialization of the Serialized
			* @param serObj contains the serialized object
			* @return true on success
			*/
			bool Deserialize(const Serialized& serObj);

			/**
			* Gets the precomputed table of [(q/qi)^{-1}]_qi / qi
			*
			* @return the precomputed table
			*/
			const std::vector<double>& GetDCRTPolyDecryptionTable() const { return m_DCRTPolyDecryptionTable; }

			/**
			* Gets the precomputed table of delta mod qi
			*
			* @return the precomputed table
			*/
			const std::vector<native_int::BigInteger>& GetDCRTPolyDeltaTable() const { return m_DCRTPolyDeltaTable; }

			/**
			* Gets the precomputed table of (q/qi)^{-1} mod qi
			*
			* @return the precomputed table
			*/
			const std::vector<native_int::BigInteger>& GetDCRTPolyInverseTable() const { return m_DCRTPolyInverseTable; }

			const std::vector<native_int::BigInteger>& GetDCRTPolyDecryptionIntTable() const { return m_DCRTPolyDecryptionIntTable; }

			const std::vector<std::vector<native_int::BigInteger>>& GetDCRTPolyqDivqiModsiTable() const { return m_DCRTPolyqDivqiModsiTable; }

			const std::vector<native_int::BigInteger>& GetDCRTPolyqModsiTable() const { return m_DCRTPolyqModsiTable; }

			const shared_ptr<ILDCRTParams<BigInteger>> GetDCRTParamsS() const { return m_paramsS; }

			const shared_ptr<ILDCRTParams<BigInteger>> GetDCRTParamsQS() const { return m_paramsQS; }

			const std::vector<double>& GetDCRTPolyMultFloatTable() const { return m_DCRTPolyMultFloatTable; }

			const std::vector<std::vector<native_int::BigInteger>>& GetDCRTPolyMultIntTable() const { return m_DCRTPolyMultIntTable; }

			const std::vector<native_int::BigInteger>& GetDCRTPolySInverseTable() const { return m_DCRTPolySInverseTable; }

			const std::vector<std::vector<native_int::BigInteger>>& GetDCRTPolysDivsiModqiTable() const { return m_DCRTPolysDivsiModqiTable; }

			const std::vector<native_int::BigInteger>& GetDCRTPolysModqiTable() const { return m_DCRTPolysModqiTable; }

			/**
			* Sets the precomputation table of [(q/qi)^{-1}]_qi / qi
			*
			* @param &DCRTPolyDecryptionTable is the precomputed table
			*/
			void SetDCRTPolyDecryptionTable(const std::vector<double> &DCRTPolyDecryptionTable) {
				m_DCRTPolyDecryptionTable = DCRTPolyDecryptionTable;
			}

			/**
			* Sets the precomputation table of delta mod qi
			*
			* @param &DCRTPolyDeltaTable is the precomputed table
			*/
			void SetDCRTPolyDeltaTable(const std::vector<native_int::BigInteger> &DCRTPolyDeltaTable) {
				m_DCRTPolyDeltaTable = DCRTPolyDeltaTable;
			}

			/**
			* Sets the precomputation table of (q/qi)^{-1} mod qi
			*
			* @param &DCRTPolyInverseTable is the precomputed table
			*/
			void SetDCRTPolyInverseTable(const std::vector<native_int::BigInteger> &DCRTPolyInverseTable) {
				m_DCRTPolyInverseTable = DCRTPolyInverseTable;
			}

			void SetDCRTPolyDecryptionIntTable(const std::vector<native_int::BigInteger> &DCRTPolyDecryptionIntTable) {
				m_DCRTPolyDecryptionIntTable = DCRTPolyDecryptionIntTable;
			}

			void SetDCRTPolyqDivqiModsiTable(const std::vector<std::vector<native_int::BigInteger>> &DCRTPolyqDivqiModsiTable) {
				m_DCRTPolyqDivqiModsiTable= DCRTPolyqDivqiModsiTable;
			}

			void SetDCRTPolyqModsiTable(const std::vector<native_int::BigInteger> &DCRTPolyqModsiTable) {
				m_DCRTPolyqModsiTable = DCRTPolyqModsiTable;
			}

			void SetDCRTParamsS(shared_ptr<ILDCRTParams<BigInteger>> paramsS) {
				m_paramsS = paramsS;
			}

			void SetDCRTParamsQS(shared_ptr<ILDCRTParams<BigInteger>> paramsQS) {
				m_paramsQS = paramsQS;
			}

			void SetDCRTPolyMultFloatTable(const std::vector<double> &DCRTPolyMultFloatTable) {
				m_DCRTPolyMultFloatTable = DCRTPolyMultFloatTable;
			}

			void SetDCRTPolyMultIntTable(const std::vector<std::vector<native_int::BigInteger>> &DCRTPolyMultIntTable) {
				m_DCRTPolyMultIntTable= DCRTPolyMultIntTable;
			}

			void SetDCRTPolySInverseTable(const std::vector<native_int::BigInteger> &DCRTPolySInverseTable) {
				m_DCRTPolySInverseTable = DCRTPolySInverseTable;
			}

			void SetDCRTPolysDivsiModqiTable(const std::vector<std::vector<native_int::BigInteger>> &DCRTPolysDivsiModqiTable) {
				m_DCRTPolysDivsiModqiTable= DCRTPolysDivsiModqiTable;
			}

			void SetDCRTPolysModqiTable(const std::vector<native_int::BigInteger> &DCRTPolysModqiTable) {
				m_DCRTPolysModqiTable = DCRTPolysModqiTable;
			}


			/**
			* == operator to compare to this instance of LPCryptoParametersBFVrns object.
			*
			* @param &rhs LPCryptoParameters to check equality against.
			*/
			bool operator==(const LPCryptoParameters<Element> &rhs) const {
				const LPCryptoParametersBFVrns<Element> *el = dynamic_cast<const LPCryptoParametersBFVrns<Element> *>(&rhs);

				if( el == 0 ) return false;

				return  LPCryptoParametersRLWE<Element>::operator==(rhs);
			}

			void PrintParameters(std::ostream& os) const {
				LPCryptoParametersRLWE<Element>::PrintParameters(os);
			}

		private:

			// DCRTPoly decryption ratios; stores a precomputed table of [(q/qi)^{-1}]_qi / qi
			std::vector<double> m_DCRTPolyDecryptionTable;

			// DCRTPoly delta table; stores precomputed floor(q/p) mod qi
			std::vector<native_int::BigInteger> m_DCRTPolyDeltaTable;

			// DCRTPoly - precomputed (q/qi)^{-1} mod qi table
			std::vector<native_int::BigInteger> m_DCRTPolyInverseTable;

			std::vector<native_int::BigInteger> m_DCRTPolyDecryptionIntTable;

			// DCRTPoly - precomputed (q/qi) mod si table
			std::vector<std::vector<native_int::BigInteger>> m_DCRTPolyqDivqiModsiTable;

			// DCRTPoly - precomputed q mod si table
			std::vector<native_int::BigInteger> m_DCRTPolyqModsiTable;

			shared_ptr<ILDCRTParams<BigInteger>> m_paramsS;

			shared_ptr<ILDCRTParams<BigInteger>> m_paramsQS;

			// DCRTPoly - precomputed Floor[p*S*[(Q*S/vi)^{-1}]_vi/vi] mod si table
			std::vector<std::vector<native_int::BigInteger>> m_DCRTPolyMultIntTable;

			// DCRTPoly - stores a precomputed table of [p*S*(Q*S/vi)^{-1}]_vi / vi
			std::vector<double> m_DCRTPolyMultFloatTable;

			// DCRTPoly - precomputed (S/si)^{-1} mod si table
			std::vector<native_int::BigInteger> m_DCRTPolySInverseTable;

			// DCRTPoly - precomputed (S/si) mod qi table
			std::vector<std::vector<native_int::BigInteger>> m_DCRTPolysDivsiModqiTable;

			// DCRTPoly - precomputed S mod qi table
			std::vector<native_int::BigInteger> m_DCRTPolysModqiTable;

	};

	/**
	* @brief Parameter generation for BFVrns.
	*
 	* The FV scheme parameter guidelines are introduced here:
 	*   - Junfeng Fan and Frederik Vercauteren. Somewhat Practical Fully Homomorphic Encryption.  Cryptology ePrint Archive, Report 2012/144. (https://eprint.iacr.org/2012/144.pdf)
 	*
 	* We used the optimized parameter selection from the designs here:
 	*   - Lepoint T., Naehrig M. (2014) A Comparison of the Homomorphic Encryption Schemes FV and YASHE. In: Pointcheval D., Vergnaud D. (eds) Progress in Cryptology – AFRICACRYPT 2014. AFRICACRYPT 2014. Lecture Notes in Computer Science, vol 8469. Springer, Cham. (https://eprint.iacr.org/2014/062.pdf)
 	*
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmParamsGenBFVrns : public LPAlgorithmParamsGenFV<Element> {
	public:

		/**
		 * Default constructor
		 */
		LPAlgorithmParamsGenBFVrns() {}

		/**
		* Method for computing all derived parameters based on chosen primitive parameters
		*
		* @param cryptoParams the crypto parameters object to be populated with parameters.
		* @param evalAddCount number of EvalAdds assuming no EvalMult and KeySwitch operations are performed.
		* @param evalMultCount number of EvalMults assuming no EvalAdd and KeySwitch operations are performed.
		* @param keySwitchCount number of KeySwitch operations assuming no EvalAdd and EvalMult operations are performed.
		*/
		bool ParamsGen(shared_ptr<LPCryptoParameters<Element>> cryptoParams, int32_t evalAddCount = 0,
			int32_t evalMultCount = 0, int32_t keySwitchCount = 0) const;

	};

	/**
	* @brief Encryption algorithm implementation for BFVrns for the basic public key encrypt, decrypt and
	* key generation methods for the BFVrns encryption scheme.
	*
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmBFVrns : public LPAlgorithmFV<Element> {
	public:

		/**
		 * Default constructor
		 */
		LPAlgorithmBFVrns() {}

		/**
		* Method for encrypting plaintext using BFVrns.
		*
		* @param publicKey public key used for encryption.
		* @param &plaintext the plaintext input.
		* @param doEncryption encrypts if true, embeds (encodes) the plaintext into cryptocontext if false
		* @return ciphertext which results from encryption.
		*/
		shared_ptr<Ciphertext<Element>> Encrypt(const shared_ptr<LPPublicKey<Element>> publicKey,
			Poly &plaintext, bool doEncryption = true) const;

		/**
		* Method for decrypting using BFVrns. See the class description for citations on where the algorithms were
	 	* taken from.
		*
		* @param privateKey private key used for decryption.
		* @param ciphertext ciphertext to be decrypted.
		* @param *plaintext the plaintext output.
		* @return the decrypted plaintext returned.
		*/
		DecryptResult Decrypt(const shared_ptr<LPPrivateKey<Element>> privateKey,
			const shared_ptr<Ciphertext<Element>> ciphertext,
			Poly *plaintext) const;


	};

	/**
	* @brief SHE algorithms implementation for BFVrns.
	*
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmSHEBFVrns : public LPAlgorithmSHEFV<Element> {
	public:

		/**
		 * Default constructor
		 */
		LPAlgorithmSHEBFVrns() {}


	};

	/**
	* @brief PRE algorithms implementation for BFVrns.
	*
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPAlgorithmPREBFVrns : public LPAlgorithmPREFV<Element> {
	public:

		/**
		 * Default constructor
		 */
		LPAlgorithmPREBFVrns() {}


	};


	/**
	 * @brief Concrete class for the FHE Multiparty algorithms on BFVrns.  A version of this multiparty scheme built on the BGV scheme is seen here:
	 *   - Asharov G., Jain A., López-Alt A., Tromer E., Vaikuntanathan V., Wichs D. (2012) Multiparty Computation with Low Communication, Computation and Interaction via Threshold FHE. In: Pointcheval D., Johansson T. (eds) Advances in Cryptology – EUROCRYPT 2012. EUROCRYPT 2012. Lecture Notes in Computer Science, vol 7237. Springer, Berlin, Heidelberg
	 *
	 * During offline key generation, this multiparty scheme relies on the clients coordinating their public key generation.  To do this, a single client generates a public-secret key pair.
	 * This public key is shared with other keys which use an element in the public key to generate their own public keys.
	 * The clients generate a shared key pair using a scheme-specific approach, then generate re-encryption keys.  Re-encryption keys are uploaded to the server.
	 * Clients encrypt data with their public keys and send the encrypted data server.
	 * The data is re-encrypted.  Computations are then run on the data.
	 * The result is sent to each of the clients.
	 * One client runs a "Leader" multiparty decryption operation with its own secret key.  All other clients run a regular "Main" multiparty decryption with their own secret key.
	 * The resulting partially decrypted ciphertext are then fully decrypted with the decryption fusion algorithms.
	 *
	 * @tparam Element a ring element.
	 */
	template <class Element>
	class LPAlgorithmMultipartyBFVrns : public LPAlgorithmMultipartyFV<Element> {
	public:

		/**
		* Default constructor
		*/
		LPAlgorithmMultipartyBFVrns() {}

	};


	/**
	* @brief Main public key encryption scheme for BFVrns implementation,
	* @tparam Element a ring element.
	*/
	template <class Element>
	class LPPublicKeyEncryptionSchemeBFVrns : public LPPublicKeyEncryptionScheme<Element> {
	public:
		LPPublicKeyEncryptionSchemeBFVrns();

		bool operator==(const LPPublicKeyEncryptionScheme<Element>& sch) const {
			if( dynamic_cast<const LPPublicKeyEncryptionSchemeBFVrns<Element> *>(&sch) == 0 )
				return false;
			return true;
		}

		void Enable(PKESchemeFeature feature);
	};

} // namespace lbcrypto ends
#endif
