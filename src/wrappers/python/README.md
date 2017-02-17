For Ubuntu

Install python 2.x if needed
sudo apt-get install python-dev

Install boost_python if needed
sudo apt-get install libboost-python-dev

Go to the root folder of the repo.

export LD_LIBRARY_PATH='pwd`/bin/lib:$LD_LIBRARY_PATH
export PYTHONPATH=`pwd`/bin/lib:$PYTHONPATH

Run the following commands:

make pywrapper
python src/wrappers/python/test.py

======================================================

Instructions for Windows and Mac will be added later

