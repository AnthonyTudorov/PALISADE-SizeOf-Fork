/**
 * @file stringencoding.h Represents and defines string-encoded plaintext objects in Palisade.
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

#include "stringencoding.h"

namespace lbcrypto {

bool
StringEncoding::Encode() {
	if( this->isEncoded ) return true;
	int64_t mod = this->encodingParams->GetPlaintextModulus().ConvertToInt();

	if( mod != 1<<8 ) {
		throw std::logic_error("Plaintext modulus must be 1<<8 for string encoding");
	}

	this->encodedVector.SetValuesToZero();
	for( size_t i=0; i<ptx.size(); i++)
		this->encodedVector.SetValAtIndex(i, ptx[i]);

	this->isEncoded = true;
	return true;
}

bool
StringEncoding::Decode() {
	int64_t mod = this->encodingParams->GetPlaintextModulus().ConvertToInt();
	this->ptx.clear();
	for( size_t i=0; i<encodedVector.GetLength(); i++)
		this->ptx += (char)((this->encodedVector.GetValAtIndex(i).ConvertToInt() % mod)&0xff);
	return true;
}

} /* namespace lbcrypto */
