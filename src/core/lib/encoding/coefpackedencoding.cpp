/**
 * @file coefpackedencoding.h Represents and defines packing integers of plaintext objects into polynomial coefficients in Palisade.
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

#include "coefpackedencoding.h"

namespace lbcrypto {

bool
CoefPackedEncoding::Encode() {
	if( this->isEncoded ) return true;
	PlaintextModulus mod = this->encodingParams->GetPlaintextModulus();
	PlaintextModulus bound = this->isSigned ? mod/2 : mod;

	if( this->isSigned && mod % 2 != 0 ) {
		throw std::logic_error("Plaintext modulus must be an even number for signed CoefPackedEncoding");
	}

	if( this->typeFlag == IsNativePoly ) {
		this->encodedNativeVector.SetValuesToZero();

		for( size_t i=0; isSigned ? i < valueSigned.size() : i < value.size(); i++ ) {
			uint32_t entry = isSigned ? (uint32_t)valueSigned[i] : value[i];
			if( isSigned ) {
				if( valueSigned[i] >= (int64_t)bound || valueSigned[i] < -(int64_t)bound )
					throw std::logic_error("Cannot encode integer " + std::to_string(entry) +
							" at position " + std::to_string(i) +
							" that is > plaintext modulus " + std::to_string(mod) );
				if( valueSigned[i] < 0 ) {
					entry += mod;
				}
			}
			else {
				if( entry >= bound )
					throw std::logic_error("Cannot encode integer " + std::to_string(entry) +
							" at position " + std::to_string(i) +
							" that is > plaintext modulus " + std::to_string(mod) );
			}

			this->encodedNativeVector[i] = entry;
		}
	}
	else {
		this->encodedVector.SetValuesToZero();

		for( size_t i=0; isSigned ? i < valueSigned.size() : i < value.size(); i++ ) {
			uint32_t entry = isSigned ? (uint32_t)valueSigned[i] : value[i];
			if( isSigned ) {
				if( valueSigned[i] >= (int64_t)bound || valueSigned[i] < -(int64_t)bound )
					throw std::logic_error("Cannot encode integer " + std::to_string(entry) +
							" at position " + std::to_string(i) +
							" that is > plaintext modulus " + std::to_string(mod) );
				if( valueSigned[i] < 0 ) {
					entry += mod;
				}
			}
			else {
				if( entry >= bound )
					throw std::logic_error("Cannot encode integer " + std::to_string(entry) +
							" at position " + std::to_string(i) +
							" that is > plaintext modulus " + std::to_string(mod) );
			}
			this->encodedVector[i] = entry;
		}
	}

	if( this->typeFlag == IsDCRTPoly ) {
		this->encodedVectorDCRT = this->encodedVector;
	}

	this->isEncoded = true;
	return true;
}

template<typename P>
static void fillVec(const P& poly, const PlaintextModulus& mod, bool isSigned, vector<uint64_t>& value, vector<int64_t>& valueSigned) {
	value.clear();
	valueSigned.clear();

	for( size_t i = 0; i < poly.GetLength(); i++ ) {
		uint64_t val = poly[i].ConvertToInt();
		if( isSigned ) {
			if( val >  mod/2)
				val -= mod;
			valueSigned.push_back(val);
		}
		else
			value.push_back(val);
	}
}

bool
CoefPackedEncoding::Decode() {

	PlaintextModulus mod = this->encodingParams->GetPlaintextModulus();

	if( this->typeFlag == IsNativePoly ) {
		fillVec(this->encodedNativeVector, mod, isSigned, this->value, this->valueSigned);
	}
	else {
		fillVec(this->encodedVector, mod, isSigned, this->value, this->valueSigned);
	}

	return true;
}


} /* namespace lbcrypto */
