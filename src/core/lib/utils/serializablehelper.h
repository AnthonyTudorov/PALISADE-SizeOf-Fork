
/**
 * @file serializablehelper.h Helper methods for serialization.
 * @author  TPOC: palisade@njit.edu
 *
 * @copyright Copyright (c) 2017, New Jersey Institute of Technology
 * (NJIT) All rights reserved.  Redistribution and use in source and
 * binary forms, with or without modification, are permitted provided
 * that the following conditions are met:

 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.

 * 2. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.

 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */ 

#ifndef LBCRYPTO_SERIALIZABLEHELPER_H
#define LBCRYPTO_SERIALIZABLEHELPER_H

#include "serializable.h"

#include "cereal/external/rapidjson/encodings.h"
#include "cereal/external/rapidjson/filereadstream.h"
#include "cereal/external/rapidjson/filewritestream.h"
#include "cereal/external/rapidjson/error/en.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <map>
#include <iterator>
#include <algorithm>
#include <cassert>

#include "../math/backend.h"
#include "../lattice/backend.h"
#include "../math/matrix.h"

namespace lbcrypto {

  class SerializableHelper {

  public:
    /**
     * Saves a serialized Palisade object's JSON string to file
     * @param serObj is the serialized object
     * @param outputFileName is the name of the file to save JSON data string to.
     * @return success or failure
     */
    static bool WriteSerializationToFile(const Serialized& serObj, std::string outputFileName);

    /**
     * Read a serialized Palisade object from a JSON file
     * @param jsonFileName is the file to read in for the Palisade object's 
     * nested serialized JSON data structure.
     * @param map containing the serialized object read from the file
     * @return success or failure
     */
    static bool ReadSerializationFromFile(const std::string jsonFileName, Serialized* map, bool verbose=false);

  };

}

#endif
