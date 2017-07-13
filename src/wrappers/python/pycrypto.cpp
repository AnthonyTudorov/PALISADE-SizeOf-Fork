//PYTHON WRAPPER
#define BOOST_PYTHON_STATIC_LIB //needed for Windows

#include <boost/python.hpp>

#include "conjinterface.h"

using namespace std;
using namespace boost::python;

BOOST_PYTHON_MODULE(pycrypto) {

    // no_init tells boost.python that Ciphertext's constructor shouldn't be accessed by the Python interface.
    // Whenever a pointer is returned, a return_value_policy<manage_new_object>() is specified to tell Python that it should
    // take responsibility over the object and delete it when not used anymore (to avoid memory leaks). If no return_value_policy
    // is specified, a compilation error will occur.
    // staticmethod is important to specify when a static method is involved, or else a compilation error will occur.
	class_<pycrypto::Obfuscator >("Obfuscator")
		.def("Initialize", &pycrypto::Obfuscator::Initialize)
		.def("Evaluate", &pycrypto::Obfuscator::Evaluate)
		.def("EvaluateClear", &pycrypto::Obfuscator::EvaluateClear);


}
