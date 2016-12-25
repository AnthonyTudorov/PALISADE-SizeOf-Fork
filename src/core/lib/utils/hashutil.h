#ifndef _SRC_LIB_UTILS_HASHUTIL_H
#define _SRC_LIB_UTILS_HASHUTIL_H
#include "../encoding/byteplaintextencoding.h"

enum HashAlgorithm { SHA_256 = 0, SHA_512 = 1 };

class HashUtil {
public:
	static lbcrypto::BytePlaintextEncoding Hash(lbcrypto::BytePlaintextEncoding message, HashAlgorithm algo) {
		switch (algo) {
		case SHA_256:
			return SHA256(message);
		case SHA_512:
		  std::cerr <<"error SHA512 disabled, returning SHA256 instead"<<std::endl;
			return SHA256(message);
		default:
			throw std::logic_error("ERROR: Unknown Hash Algorithm");
			return lbcrypto::BytePlaintextEncoding();
		}
	}
private:
	static lbcrypto::BytePlaintextEncoding SHA256(lbcrypto::BytePlaintextEncoding message);
	static lbcrypto::BytePlaintextEncoding SHA512(lbcrypto::BytePlaintextEncoding message);
	static const uint32_t k_256[64];
	static const uint64_t k_512[80];
};

#endif
