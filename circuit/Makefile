OPTIONS = -std=c++11 -DCURVE_ALT_BN128 -DNO_PROCPS -ggdb -DDEBUG
LIBS    = -lsnark -lff -lgmp -lstdc++ -lprocps -lgmpxx
GCC			= g++

circuit: main.cpp
	$(GCC) $< -o $@ $(OPTIONS) $(INCLUDE) $(LIBS)
