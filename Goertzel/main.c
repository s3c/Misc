#include "Goertzel.h"

int main(void){
	Goertzel t1(1000, 50);
	
	t1.AddBin(10);
	t1.AddBin(20);
	t1.AddBin(30);
	
	t1.RemoveBin(20);
	
	return 1;
}
