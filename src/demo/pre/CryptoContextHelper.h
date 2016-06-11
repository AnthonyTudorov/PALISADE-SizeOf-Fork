/*
 * CryptoContextHelper.h
 *
 *  Created on: May 27, 2016
 *      Author: gwryan
 */

#ifndef SRC_DEMO_PRE_CRYPTOCONTEXTHELPER_H_
#define SRC_DEMO_PRE_CRYPTOCONTEXTHELPER_H_

#include <string>
#include "utils/serializablehelper.h"

extern void printAllParmSets(ostream&out, const std::string& fn);
extern void printAllParmSetNames(ostream&out, const std::string& fn);
extern CryptoContext *getNewContext(const string& parmfile, const string& parmsetname);
extern CryptoContext *getNewContext(const string& parmSetJson);

#endif /* SRC_DEMO_PRE_CRYPTOCONTEXTHELPER_H_ */
