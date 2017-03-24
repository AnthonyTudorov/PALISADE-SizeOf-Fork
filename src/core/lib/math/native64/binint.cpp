#include "binint.h"

#ifdef _MSC_VER
namespace native64 {

UsageMessage::UsageMessage() {
	std::cout << "Warning: Operations on native64 integers may overflow and not be detected in this version of Visual Studio" << std::endl;
}

static UsageMessage PrintUsageMessageAtStart;

}
#endif
