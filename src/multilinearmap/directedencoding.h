#include "../utils/inttypes.h"
/**
 *  @brief Square matrix of ring elements
 *
 */
template<class Element>
class EncodedElement {

};

template <class Element>
class KeyPair {
public:
    Element publicKey;
    EncodedElement<Element> encodingKey;
}
template<class Element>
class DirectedEncoding {
public:
    static KeyPair Setup(usint securityParameter, usint maxLevels);
    static EncodedElement<Element> Encode(KeyPair source, Element targetPK, Element m);
    static EncodedElement<Element> Multiply(EncodedElement e1, EncodedElement e2);
    static bool Equals(EncodedElement e1, EncodedElement e2);
};
