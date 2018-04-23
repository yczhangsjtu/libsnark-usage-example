OPTIONS = -std=c++11 -DCURVE_ALT_BN128 -DNO_PROCPS -ggdb
LIBS    = -lsnark -lff -lgmp -lstdc++ -lprocps -lgmpxx
GCC			= g++

sha256: demo_sha256.cpp
	$(GCC) $< -o $@ $(OPTIONS) $(INCLUDE) $(LIBS)
