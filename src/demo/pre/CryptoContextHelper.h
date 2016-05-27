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

extern void printAllParmSets(const std::string& fn);
extern CryptoContext *getNewContext(const string& parmfile, const string& parmset);

#endif /* SRC_DEMO_PRE_CRYPTOCONTEXTHELPER_H_ */
