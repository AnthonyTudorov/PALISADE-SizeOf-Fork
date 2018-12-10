#include "signaturecontext.h"
#include "signaturecontext.cpp"

namespace lbcrypto{
    template class SignatureContext<Poly>;
    
    template class SignatureContext<NativePoly>;


}