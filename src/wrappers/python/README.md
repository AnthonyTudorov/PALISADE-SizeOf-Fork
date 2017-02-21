For Ubuntu
----------
****

* Install python 2.x if needed

> sudo apt-get install python-dev

* Install boost_python if needed

> sudo apt-get install libboost-python-dev

* Go to the root folder of the repo.

> export LD_LIBRARY_PATH=&#96;pwd&#96;/bin/lib:$LD_LIBRARY_PATH

> export PYTHONPATH=&#96;pwd&#96;/bin/lib:$PYTHONPATH

* Run the following commands

> make pywrapper

> python src/wrappers/python/test.py


For Windows + Visual Studio 2015
----------
****

1. Install Python 2.X (64-bit version)

2. Install the boost library:
  * Download a the appropriate version of boost at http://www.boost.org/ and extract it to c:\boost_xxx <br>
    [Note: as of this writing, the latest build is using boost_1_62_0, but please check with project leads first, as these instructions can become out of date].
  * Run VS2015 x64 Native Tools Command Prompt (under Visual Studio 2015 -> Visual Studio Tools -> Windows Desktop Command Prompts) as administrator.
  * Go to the boost directory
  * Execute "bootstrap" to build the Boost.Build engine
  * Execute "b2 address-model=64 toolset=msvc-14.0" to build object files (specify the right version; 14.0 corresponds to VS 2015)
  
3. (Optional - this step is needed when not using the Visual Studio Solution in ide/vs2015). Add paths to Visual Studio project:
  * Add "c:\boost_xxx" to the VC++ include directories
  * Add "c:\boost_xxx\stage\lib" to the VC++ library directories
  * Add c:\pytonXX\include to VC++ include directories
  * Add c:\pythonXX\libs to VC++ library directories
  * Add c:\pythonXX\libs to VC++ Linker directories (Additional Library directories under Linker)

4. Compile as DLL, copy the dll to the folder where python.exe resides (or update PYTHON_PATH), and rename it as pycrypto.pyd

5. Run "python test.py" from the src/wrappers/python/ folder