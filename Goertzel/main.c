//reset; g++ main.c Goertzel.cc -o Goertzel -std=c++11 -Wall

#include "Goertzel.h"

int main(void){
	Goertzel t1(1000, 50);
	
	t1.AddBin(10);
	t1.AddBin(20);
	t1.AddBin(30);
	
	for(int i = 0; i < 1000; i++)
		t1.ProcessSample(i);
	
	t1.RemoveBin(20);
	
	return 1;
}
