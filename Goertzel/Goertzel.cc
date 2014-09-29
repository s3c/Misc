#include <stdexcept>
#include <exception>
#include "Goertzel.h"

Goertzel::Goertzel(float set_samp_freq, unsigned int set_samp_count){
	if(set_samp_freq < 1 || set_samp_count < 1)
		throw std::range_error("Value out of range, frequency and sample count should be at least 1");
	samp_freq_ = set_samp_freq;
	samp_count_ = set_samp_count;
}	

void Goertzel::AddBin(float det_freq, float mag_trig){
	if(det_freq < 1)
		throw std::range_error("Value out of range, frequency should be at least 1");
	//add coef to init
	Bin newbin = {0, 0, 0, det_freq, 0, mag_trig, 0};
	bins_.push_back(newbin);
}

void Goertzel::RemoveBin(float det_freq){
	for(auto i = bins_.begin(); i != bins_.end(); i++){
		if(i->freq == det_freq){
			bins_.erase(i);
			return;
		}
	}
	throw std::invalid_argument("Bin not found");
}

void Goertzel::ProcessSample(float samp_value){
}

unsigned int Goertzel::LastMagValue(float freq){
}

bool Goertzel::LastMagTrig(float freq){
}

void Goertzel::ResetBins(void){
}
