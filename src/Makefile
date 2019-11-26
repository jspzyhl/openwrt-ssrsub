# build hellocpp executable when user executes "make"
ssrsub: main.o
	$(CXX) $(LDFLAGS) main.o -o ssrsub -luci

main.o: main.cpp
	$(CXX) $(CXXLAGS) -c main.cpp -std=c++11

# remove object files and executable when user executes "make clean"
clean:
	rm *.o hellocpp

