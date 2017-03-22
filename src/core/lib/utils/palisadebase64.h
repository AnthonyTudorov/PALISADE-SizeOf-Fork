/*
 * palisadebase64.h
 *
 *  Created on: Mar 16, 2017
 *      Author: gwryan
 */

#ifndef SRC_CORE_LIB_UTILS_PALISADEBASE64_H_
#define SRC_CORE_LIB_UTILS_PALISADEBASE64_H_

#include <cctype>
#include <cstdint>
#include <stdexcept>

namespace lbcrypto {

	extern const char to_base64_char[];

	inline unsigned char value_to_base64(int c) {
		return to_base64_char[c];
	}

	inline unsigned char base64_to_value(unsigned char b64) {
		if( isupper(b64) )
			return b64 - 'A';
		else if( islower(b64) )
			return b64 - 'a' + 26;
		else if( isdigit(b64) )
			return b64 - '0' + 52;
		else if( b64 == '+' )
			return 62;
		else
			return 63;
	}

	inline unsigned char get_6bits_atoffset(uint64_t m_value, uint32_t index) {
		static unsigned char smallmask[] = { 0, 0x1, 0x3, 0x7, 0xf, 0x1f, 0x3f };

		if(index==0) {
			throw std::logic_error("Zero index in GetBitAtIndex");
		}
		if( index<=6 ) {
			return m_value & smallmask[index];
		}

		return (m_value >> (index-6)) & 0x3f;
	}



} /* namespace lbcrypto */

#endif /* SRC_CORE_LIB_UTILS_PALISADEBASE64_H_ */
