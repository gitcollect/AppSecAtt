all:
	@g++ -o attack -std=c++11 -O3 attack.cpp -fopenmp -lgmp -lgmpxx -lcrypto -fopenmp

debug:
	@g++ -o attack -std=c++11 -g attack.cpp -fopenmp -lgmp -lgmpxx -lcrypto -fopenmp

clean :
	@rm -f attack