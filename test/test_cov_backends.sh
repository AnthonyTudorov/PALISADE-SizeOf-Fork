
backends="2 4 6 7"

if [ "$1" != "" ];
then
	backends=$1
fi

for i in $backends
do
	lib=bin/backend-${i}-cov/lib
	ex=bin/backend-${i}-cov/unittest/tests

	echo "****************************"
	echo Coverage test MATHBACKEND $i
	echo "****************************"
	if [[ -x $ex ]]
	then
		(
			# set paths for mac or linux or win
		export DYLD_LIBRARY_PATH=$lib:$DYLD_LIBRARY_PATH
		export LD_LIBRARY_PATH=$lib:$LD_LIBRARY_PATH
		export PATH=$lib:$PATH
		$ex -t

		##gcov -m -r `find bin/backend-${i}-cov -name '*.gcda'`
		##rm -fr bin/backend-${i}-cov/gcov
		##mkdir bin/backend-${i}-cov/gcov
		##mv *.gcov bin/backend-${i}-cov/gcov
		lcov --capture --directory bin/backend-${i}-cov -o bin/backend-${i}-cov/coverage.out
		genhtml -q -o bin/backend-${i}-cov/html bin/backend-${i}-cov/coverage
		)
		echo "****************************"
		echo COVERAGE TEST DONE
		echo "****************************"
	else
		echo " ******** $ex for MATHBACKEND $i not found"
	fi
done