/*
 * cryptocontextparametersets.h
 *
 *  Created on: Oct 7, 2016
 *      Author: gwryan
 */

#ifndef SRC_LIB_UTILS_CRYPTOCONTEXTPARAMETERSETS_H_
#define SRC_LIB_UTILS_CRYPTOCONTEXTPARAMETERSETS_H_

#include <map>
#include <string>
using std::map;
using std::string;

namespace lbcrypto {

extern map<string, map<string,string>> CryptoContextParameterSets;

inline bool knownParameterSet(string p) { return CryptoContextParameterSets.find(p) != CryptoContextParameterSets.end(); }

} /* namespace lbcrypto */

#endif /* SRC_LIB_UTILS_CRYPTOCONTEXTPARAMETERSETS_H_ */
