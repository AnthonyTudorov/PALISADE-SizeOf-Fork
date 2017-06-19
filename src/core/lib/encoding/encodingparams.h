/**
 * @file encodingparams.h Represents and defines parameters for plaintext encoding.
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

#ifndef LBCRYPTO_ENCODING_ENCODINGPARAMS_H
#define LBCRYPTO_ENCODING_ENCODINGPARAMS_H

#include "../math/backend.h"

namespace lbcrypto
{
/**
 * @class EncodingParamsImpl
 * @brief defining EncodingParams.
 */
template<typename IntType> class EncodingParamsImpl;
/**
 * @brief defining typedef  EncodingParamsImpl<BigBinaryInteger> as EncodingParams. 
 */
typedef EncodingParamsImpl<BigBinaryInteger> EncodingParams;
}

namespace lbcrypto
{

/**
 * @class EncodingParamsImpl
 * @brief Templated serializable parameters for plaintext encodings defines plaintext space.
 */
template<typename IntType>
class EncodingParamsImpl : public Serializable
{
public:

	/**
	 * Main constructor. Supports (1) default constructor, (2) regular encoding with plaintext modulus set,
	 * (3) packed encoding with at least first two parameters set.
	 * All of the private members not explicitly included as aerguments will be initialized to zero.
	 *
	 * @param plaintextModulus plainext modulus (used by all encodings)
	 * @param plaintextGenerator (used by packed encoding for plaintext slot rotation)
	 * @param batchSize sets the maximum batch size (as a power of 2) needed for EvalSum
	 */
	EncodingParamsImpl(
	    const IntType& plaintextModulus = IntType::ZERO,
	    const IntType& plaintextGenerator = IntType::ZERO,
	    usint batchSize = 0) {
		m_plaintextModulus = plaintextModulus;
		m_plaintextGenerator = plaintextGenerator;
		m_batchSize = batchSize;
	}

	/**
	 * Copy constructor.
	 *
	 * @param &rhs the input set of parameters which is copied.
	 */
	EncodingParamsImpl(const EncodingParamsImpl &rhs) {
		m_plaintextModulus = rhs.m_plaintextGenerator;
		m_plaintextGenerator = rhs.m_plaintextGenerator;
		m_batchSize = rhs.m_batchSize;
	}

	/**
	* Move constructor.
	*
	* @param &rhs the input set of parameters which is copied.
	*/
	EncodingParamsImpl(const EncodingParamsImpl &&rhs) {
		m_plaintextModulus = std::move(rhs.m_plaintextGenerator);
		m_plaintextGenerator = std::move(rhs.m_plaintextGenerator);
		m_batchSize = rhs.m_batchSize;
	}

	/**
	 * Assignment Operator.
	 *
	 * @param &rhs the EncodingParamsImpl to be copied.
	 * @return the resulting EncodingParamsImpl.
	 */
	const EncodingParamsImpl& operator=(const EncodingParamsImpl &rhs) {
		m_plaintextModulus = rhs.m_plaintextGenerator;
		m_plaintextGenerator = rhs.m_plaintextGenerator;
		m_batchSize = rhs.m_batchSize;
		return *this;
	}

	/**
	 * Destructor.
	 */
	virtual ~EncodingParamsImpl() {}

	// ACCESSORS

	// Get accessors
	/**
	* @brief Getter for the plaintext modulus.
	* @return The plaintext modulus.
	*/
	const IntType &GetPlaintextModulus() const {
		return m_plaintextModulus;
	}
	/**
	* @brief Getter for the plaintext generator.
	* @return The plaintext generator.
	*/
	const IntType &GetPlaintextGenerator() const {
		return m_plaintextGenerator;
	}
	/**
	* @brief Getter for the plaintext batch size.
	* @return The plaintext batch size.
	*/
	const usint GetBatchSize() const {
		return m_batchSize;
	}

	// Operators
	/**
	 * @brief output stream operator.
	 * @param out the output stream to output.
	 * @param item the following object to output.
	 * @return the string output.
	 */
	friend std::ostream& operator<<(std::ostream& out, const EncodingParamsImpl &item) {
		return item.doprint(out);
	}
	/**
	 * @brief Equality operator for the parameters.  Tests that all the parameters are equal.
	 * @param other the other parameter set to compare to.
	 * @return true if values of all data are equal.
	 */
	bool operator==(const EncodingParamsImpl<IntType> &other) const {
		return m_plaintextModulus == other.m_plaintextModulus &&
		       m_plaintextGenerator == other.m_plaintextGenerator &&
		       m_batchSize == other.m_batchSize;
	}
	/**
	 * @brief Inequality operator for the parameters.  Tests that all the parameters are not equal.
	 * @param other the other parameter set to compare to.
	 * @return true if values of any data is not equal.
	 */
	bool operator!=(const EncodingParamsImpl<IntType> &other) const {
		return !(*this == other);
	}

private:

	std::ostream& doprint(std::ostream& out) const {
		out << "[p=" << m_plaintextModulus << " g=" << m_plaintextGenerator
		    << " L=" << m_batchSize
		    << "]";
		return out;
	}

	// plaintext modulus that is used by all schemes
	IntType		m_plaintextModulus;
	// plaintext generator is used for packed encoding
	IntType		m_plaintextGenerator;
	// maximum batch size used by EvalSumKeyGen for packed encoding
	usint		m_batchSize;

public:
	/**
	 * Serialize the object into a Serialized
	 * @param serObj is used to store the serialized result. It MUST be a rapidjson Object (SetObject());
	 * @return true if successfully serialized
	 */
	bool Serialize(Serialized* serObj) const;

	/**
	 * Populate the object from the deserialization of the Setialized
	 * @param serObj contains the serialized object
	 * @return true on success
	 */
	bool Deserialize(const Serialized& serObj);
};


} // namespace lbcrypto ends

#endif