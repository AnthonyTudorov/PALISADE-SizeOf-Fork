for i in 2 4 6 7
do
	echo "****************************"
	echo Building and testing MATHBACKEND $i
	echo "****************************"
	touch src/core/lib/math/backend.h
	make -j16  BINDIR=bin/backend-$i CPPFLAGS+=-DMATHBACKEND=$i all benchmark >/dev/null 2>&1
	if [ $? -eq 0 ];
	then
		echo "****************************"
		echo BUILT
		echo "****************************"
		(
		export DYLD_LIBRARY_PATH=bin/backend-$i/lib:$LD_LIBRARY_PATH
		export LD_LIBRARY_PATH=bin/backend-$i/lib:$LD_LIBRARY_PATH
		export PATH=bin/backend-$i/lib:$LD_LIBRARY_PATH
		bin/backend-$i/unittest/tests -t
		)
		echo "****************************"
		echo TESTS DONE
		echo "****************************"
	else
		echo " ******** build for MATHBACKEND $i failed!!!"
	fi
done
