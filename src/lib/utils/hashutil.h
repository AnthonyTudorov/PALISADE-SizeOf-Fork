#ifndef _SRC_LIB_UTILS_HASHUTIL_H
#define _SRC_LIB_UTILS_HASHUTIL_H
#include "bytearray.h"

enum HashAlgorithm { SHA_256 = 0, SHA_512 = 1 };

class HashUtil {
public:
	static lbcrypto::ByteArray Hash(lbcrypto::ByteArray message, HashAlgorithm algo) {
		switch (algo) {
		case SHA_256:
			return SHA256(message);
		case SHA_512:
			return SHA512(message);
		default:
			throw std::logic_error("ERROR: Unknown Hash Algorithm");
			return lbcrypto::ByteArray();
		}
	}
private:
	static lbcrypto::ByteArray SHA256(lbcrypto::ByteArray message);
	static lbcrypto::ByteArray SHA512(lbcrypto::ByteArray message);
	static const uint32_t k_256[64];
	static const uint64_t k_512[80];
};

#endif
