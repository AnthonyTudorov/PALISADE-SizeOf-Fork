/*
 * cryptocontextparametersets.cpp
 *
 *  Created on: Oct 7, 2016
 *      Author: gwryan
 */

#include "cryptocontextparametersets.h"

namespace lbcrypto {

map<string, map<string,string>> CryptoContextParameterSets = {

		{ "LTV1" , {
				{ "parameters", "LTV" },
				{ "plaintextModulus", "2" },
				{ "ring", "2048" },
				{ "modulus", "268441601" },
				{ "rootOfUnity", "16947867" },
				{ "relinWindow", "1" },
				{ "stDev", "4" }
		} },

		{ "LTV2", {
				{ "parameters", "LTV" },
				{ "plaintextModulus", "2" },
				{ "ring",  "2048" },
				{ "modulus", "536881153" },
				{ "rootOfUnity", "267934765" },
				{ "relinWindow", "2" },
				{ "stDev", "4" }
		} },

		{ "LTV3", {
				{ "parameters", "LTV" },
				{ "plaintextModulus", "2" },
				{ "ring",  "2048" },
				{ "modulus", "1073750017" },
				{ "rootOfUnity", "180790047" },
				{ "relinWindow", "4" },
				{ "stDev", "4" }
		} },

		{ "LTV4", {
				{ "parameters", "LTV" },
				{ "plaintextModulus", "2" },
				{ "ring",  "2048" },
				{ "modulus", "8589987841" },
				{ "rootOfUnity", "2678760785" },
				{ "relinWindow", "8" },
				{ "stDev", "4" }
		} },

		{ "LTV5", {
				{ "parameters", "LTV" },
				{ "plaintextModulus", "2" },
				{ "ring",  "4096" },
				{ "modulus", "2199023288321" },
				{ "rootOfUnity", "1858080237421" },
				{ "relinWindow", "16" },
				{ "stDev", "4" }
		} },

		{ "StSt1", {
				{ "parameters", "StehleSteinfeld" },
				{ "plaintextModulus", "2" },
				{ "ring", "2048" },
				{ "modulus", "8589987841" },
				{ "rootOfUnity", "8451304774" },
				{ "relinWindow", "1" },
				{ "stDev", "4" },
				{ "stDevStSt", "98.4359" }
		} },

		{ "StSt2", {
				{ "parameters", "StehleSteinfeld" },
				{ "plaintextModulus", "2" },
				{ "ring",  "2048" },
				{ "modulus", "137439004673" },
				{ "rootOfUnity", "7643730114" },
				{ "relinWindow", "8" },
				{ "stDev", "4" },
				{ "stDevStSt", "214.9" }
		} },

		{ "StSt3", {
				{ "parameters", "StehleSteinfeld" },
				{ "plaintextModulus", "2" },
				{ "ring",  "4096" },
				{ "modulus", "17179926529" },
				{ "rootOfUnity", "1874048014" },
				{ "relinWindow", "1" },
				{ "stDev", "4" },
				{ "stDevStSt", "98.4359" }
		} },

		{ "StSt4", {
				{ "Note", "FGCS1" },
				{ "parameters", "StehleSteinfeld" },
				{ "plaintextModulus", "2" },
				{ "ring", "4096" },
				{ "modulus", "140737488486401" },
				{ "rootOfUnity", "65185722416667" },
				{ "relinWindow", "16" },
				{ "stDev", "4" },
				{ "stDevStSt", "354.34" }
		} },

		{ "StSt5", {
				{ "Note", "FGCS2" },
				{ "parameters", "StehleSteinfeld" },
				{ "plaintextModulus", "16" },
				{ "ring", "4096" },
				{ "modulus", "72057594037948417" },
				{ "rootOfUnity", "12746853818308484" },
				{ "relinWindow", "16" },
				{ "stDev", "4" },
				{ "stDevStSt", "1511.83" }
		} },

		{ "StSt6", {
				{ "Note", "FGCS Final" },
				{ "parameters", "StehleSteinfeld" },
				{ "plaintextModulus", "256" },
				{ "ring", "8192" },
				{ "modulus", "75557863725914323468289" },
				{ "rootOfUnity", "36933905409054618621009" },
				{ "relinWindow", "16" },
				{ "stDev", "4" },
				{ "stDevStSt", "41411.5" }
		} },

		{ "FV1", {
				{ "parameters", "FV" },
				{ "plaintextModulus", "4" },
				{ "securityLevel", "1.006" }
		} },

		{ "FV2", {
				{ "parameters", "FV" },
				{ "plaintextModulus", "16" },
				{ "securityLevel", "1.006" }
		} },

		{ "Null", {
				{ "parameters", "Null" },
				{ "plaintextModulus", "256" },
				{ "ring", "8192" },
				{ "modulus", "536903681" },
				{ "rootOfUnity", "242542334" }
		} },

		{ "Null2", {
				{ "parameters", "Null" },
				{ "plaintextModulus", "5" },
				{ "ring", "8" },
				{ "modulus", "536871001" },
				{ "rootOfUnity", "322299632" }
		} }


};

} /* namespace lbcrypto */
