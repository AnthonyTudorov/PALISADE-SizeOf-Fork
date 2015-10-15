#include <cstring>
#include <iostream>

#include "saveparams.h"

using namespace std;

int main(int argc, char **argv) {
  if (argc != 3) {
    cout << "Usage: " << argv[0] << " COMMAND FILENAME" << endl
         << "COMMAND: 'load' or 'save'" << endl
         << "Load will load the JSON file, FILENAME, and print out its contents." << endl
         << "Save will save a sample address book to FILENAME in JSON format." << endl;
    return 1;
  }
  AllParams All_Params;
  if (strcmp(argv[1], "load") == 0) {
    All_Params.JsonLoad("../documents/params.json");
    for (vector<Params>::const_iterator it = All_Params.params().begin(); it != All_Params.params().end(); ++it) {
      cout << (*it).get_PlaintextModulus() << "," << (*it).get_DistributionParameter() << endl;
      cout << (*it).get_AssuranceMeasure() << "," << (*it).get_SecurityLevel() << endl;
      cout << (*it).get_RelinWindow() << "," << (*it).get_Depth() << endl;
    }
  } else if (strcmp(argv[1], "save") == 0) {
    All_Params.AddParams("one", "two","three","Four","five","six");
    All_Params.JsonSave("../documents/params.json");
  }
  return 0;
}
