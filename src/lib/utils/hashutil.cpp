#ifndef _SRC_LIB_UTILS_HASHUTIL_CPP
#define _SRC_LIB_UTILS_HASHUTIL_CPP
#include "hashutil.h"
#include <boost/multiprecision/cpp_int.hpp>
#define RIGHT_ROT(x, n) (( x >> (n % (sizeof(x)*8) ) | ( x << ((sizeof(x)*8) - (n % (sizeof(x)*8))))))

using namespace boost::multiprecision;

ByteArray HashUtil::SHA256(ByteArray message) {
	
	uint32_t h_256[8] = { 0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19 };
	
	uint64_t m_len = message.size() * 8;
	uint16_t pad_len = 1;
	while ((m_len + pad_len) % 512 != 448) {
		pad_len++;
	}
	message.push_back(128);
	for (int a = 0;a < (pad_len) / 8 - 1;a++) {
		message.push_back(0);
	}
	message.push_back((uint8_t)((m_len & 0xff00000000000000) >> 56));
	message.push_back((uint8_t)((m_len & 0x00ff000000000000) >> 48));
	message.push_back((uint8_t)((m_len & 0x0000ff0000000000) >> 40));
	message.push_back((uint8_t)((m_len & 0x000000ff00000000) >> 32));
	message.push_back((uint8_t)((m_len & 0x00000000ff000000) >> 24));
	message.push_back((uint8_t)((m_len & 0x0000000000ff0000) >> 16));
	message.push_back((uint8_t)((m_len & 0x000000000000ff00) >> 8));
	message.push_back((uint8_t)(m_len & 0x00000000000000ff));


	for (int n = 0;n < (message.size() * 8) / 512; n++) {
		uint32_t w[64];
		short counter = 0;
		for (int m = 64 * n;m < (64 * (n + 1));m += 4) {
			w[counter] = ((uint32_t)message.at(m) << 24) ^ ((uint32_t)message.at(m + 1) << 16) ^ ((uint32_t)message.at(m + 2) << 8) ^ ((uint32_t)message.at(m + 3));
			std::cout << "w[" << counter << "]: " << w[counter] << std::endl;
			counter++;
		}
		for (int i = 16;i < 64;i++) {
			uint32_t s0 = ((uint32_t)RIGHT_ROT(w[i - 15], 7)) ^ ((uint32_t)(RIGHT_ROT(w[i - 15], 18))) ^ ((uint32_t)(w[i - 15] >> 3));
			uint32_t s1 = ((uint32_t)RIGHT_ROT(w[i - 2], 17)) ^ ((uint32_t)RIGHT_ROT(w[i - 2], 19)) ^ ((uint32_t)(w[i - 2] >> 10));
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}

		uint32_t a = h_256[0];
		uint32_t b = h_256[1];
		uint32_t c = h_256[2];
		uint32_t d = h_256[3];
		uint32_t e = h_256[4];
		uint32_t f = h_256[5];
		uint32_t g = h_256[6];
		uint32_t h = h_256[7];

		for (int i = 0; i < 64;i++) {
			uint32_t S1 = ((uint32_t)RIGHT_ROT(e, 6)) ^ ((uint32_t)RIGHT_ROT(e, 11)) ^ ((uint32_t)RIGHT_ROT(e, 25));
			uint32_t ch = (e & f) ^ ((~e) & g);
			uint32_t temp1 = h + S1 + ch + k_256[i] + w[i];
			uint32_t S0 = ((uint32_t)RIGHT_ROT(a, 2)) ^ ((uint32_t)RIGHT_ROT(a, 13)) ^ ((uint32_t)RIGHT_ROT(a, 22));
			uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
			uint32_t temp2 = S0 + maj;

			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;

		}

		h_256[0] += a;
		h_256[1] += b;
		h_256[2] += c;
		h_256[3] += d;
		h_256[4] += e;
		h_256[5] += f;
		h_256[6] += g;
		h_256[7] += h;
	}

	

	ByteArray digest;
	for (int i = 0; i < 8; i++) {
		digest.push_back((uint8_t)((h_256[i] & 0xff000000) >> 24));
		digest.push_back((uint8_t)((h_256[i] & 0x00ff0000) >> 16));
		digest.push_back((uint8_t)((h_256[i] & 0x0000ff00) >> 8));
		digest.push_back((uint8_t)(h_256[i] & 0x000000ff));
	}

	return digest;
}
ByteArray HashUtil::SHA512(ByteArray message) {
	
	uint64_t h_512[8] = { 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 };

	uint128_t m_len = message.size() * 8;
	uint64_t m_len_first = message.size() / (0x2000000000000000);
	uint64_t m_len_second = message.size()*8;
	uint16_t pad_len = 1;
	while ((m_len + pad_len) % 1024 != 896) {
		pad_len++;
	}
	message.push_back(128);
	for (int a = 0;a < (pad_len) / 8 - 1;a++) {
		message.push_back(0);
	}

	message.push_back((uint8_t)((m_len_first & 0xff00000000000000) >> 56));
	message.push_back((uint8_t)((m_len_first & 0x00ff000000000000) >> 48));
	message.push_back((uint8_t)((m_len_first & 0x0000ff0000000000) >> 40));
	message.push_back((uint8_t)((m_len_first & 0x000000ff00000000) >> 32));
	message.push_back((uint8_t)((m_len_first & 0x00000000ff000000) >> 24));
	message.push_back((uint8_t)((m_len_first & 0x0000000000ff0000) >> 16));
	message.push_back((uint8_t)((m_len_first & 0x000000000000ff00) >> 8));
	message.push_back((uint8_t)(m_len_first & 0x00000000000000ff));

	message.push_back((uint8_t)((m_len_second & 0xff00000000000000) >> 56));
	message.push_back((uint8_t)((m_len_second & 0x00ff000000000000) >> 48));
	message.push_back((uint8_t)((m_len_second & 0x0000ff0000000000) >> 40));
	message.push_back((uint8_t)((m_len_second & 0x000000ff00000000) >> 32));
	message.push_back((uint8_t)((m_len_second & 0x00000000ff000000) >> 24));
	message.push_back((uint8_t)((m_len_second & 0x0000000000ff0000) >> 16));
	message.push_back((uint8_t)((m_len_second & 0x000000000000ff00) >> 8));
	message.push_back((uint8_t)(m_len_second & 0x00000000000000ff));


	for (int n = 0;n < (message.size() * 8) / 1024; n++) {
		uint64_t w[80];
		short counter = 0;
		std::cout << ((uint64_t)message.at(0)) << std::endl;
		for (int m = 128 * n;m < (128 * (n + 1));m += 8) {
			w[counter] = ((uint64_t)message.at(m) << 56) ^ ((uint64_t)message.at(m+1) << 48) ^ ((uint64_t)message.at(m+2) << 40) ^ ((uint64_t)message.at(m+3) << 32) ^ ((uint64_t)message.at(m+4) << 24) ^ ((uint64_t)message.at(m + 5) << 16) ^ ((uint64_t)message.at(m + 6) << 8) ^ ((uint64_t)message.at(m + 7));
			std::cout << "w[" << counter << "]: " << w[counter] << std::endl;
			counter++;
		}
		for (int i = 16;i < 80;i++) {
			uint64_t s0 = ((uint64_t)RIGHT_ROT(w[i - 15], 1)) ^ ((uint64_t)(RIGHT_ROT(w[i - 15], 8))) ^ ((uint64_t)(w[i - 15] >> 7));
			uint64_t s1 = ((uint64_t)RIGHT_ROT(w[i - 2], 19)) ^ ((uint64_t)RIGHT_ROT(w[i - 2], 61)) ^ ((uint64_t)(w[i - 2] >> 6));
			w[i] = w[i - 16] + s0 + w[i - 7] + s1;
		}

		uint64_t a = h_512[0];
		uint64_t b = h_512[1];
		uint64_t c = h_512[2];
		uint64_t d = h_512[3];
		uint64_t e = h_512[4];
		uint64_t f = h_512[5];
		uint64_t g = h_512[6];
		uint64_t h = h_512[7];

		for (int i = 0; i < 80;i++) {
			uint64_t S1 = ((uint64_t)RIGHT_ROT(e, 14)) ^ ((uint64_t)RIGHT_ROT(e, 18)) ^ ((uint64_t)RIGHT_ROT(e, 41));
			uint64_t ch = (e & f) ^ ((~e) & g);
			uint64_t temp1 = h + S1 + ch + k_512[i] + w[i];
			uint64_t S0 = ((uint64_t)RIGHT_ROT(a, 28)) ^ ((uint64_t)RIGHT_ROT(a, 34)) ^ ((uint64_t)RIGHT_ROT(a, 39));
			uint64_t maj = (a & b) ^ (a & c) ^ (b & c);
			uint64_t temp2 = S0 + maj;

			h = g;
			g = f;
			f = e;
			e = d + temp1;
			d = c;
			c = b;
			b = a;
			a = temp1 + temp2;

		}

		h_512[0] += a;
		h_512[1] += b;
		h_512[2] += c;
		h_512[3] += d;
		h_512[4] += e;
		h_512[5] += f;
		h_512[6] += g;
		h_512[7] += h;
	}
	std::cout << h_512[0] << std::endl;


	ByteArray digest;
	for (int i = 0; i < 8; i++) {
		digest.push_back((uint8_t)((h_512[i] & 0xff00000000000000) >> 56));
		digest.push_back((uint8_t)((h_512[i] & 0x00ff000000000000) >> 48));
		digest.push_back((uint8_t)((h_512[i] & 0x0000ff0000000000) >> 40));
		digest.push_back((uint8_t)((h_512[i] & 0x000000ff00000000) >> 32));
		digest.push_back((uint8_t)((h_512[i] & 0x00000000ff000000) >> 24));
		digest.push_back((uint8_t)((h_512[i] & 0x0000000000ff0000) >> 16));
		digest.push_back((uint8_t)((h_512[i] & 0x000000000000ff00) >> 8));
		digest.push_back((uint8_t)(h_512[i] & 0x00000000000000ff));
	}

	return digest;

	
	ByteArray a;
	return a;
}



#endif