for i in 2 4 6 7
do
	echo "****************************"
	echo Building and testing MATHBACKEND $i
	echo "****************************"
	touch src/core/lib/math/backend.h
	make -j8  CPPFLAGS+=-DMATHBACKEND=$i all # -DBigIntegerBitLength=128
	make testall
	echo "****************************"
	echo DONE
	echo "****************************"
done
