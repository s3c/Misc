#include <stdexcept>
#include <exception>
#include <cmath>
#include "Goertzel.h"

Goertzel::Goertzel(unsigned int set_samp_rate, unsigned int set_samp_count){
	if(!set_samp_rate || !set_samp_count)
		throw std::range_error("Value out of range, frequency and sample count should be at least 1");
	samp_rate_ = set_samp_rate;
	samp_count_ = set_samp_count;
}	

void Goertzel::AddBin(unsigned int det_freq, float mag_trig){
	if(!det_freq)
		throw std::range_error("Value out of range, frequency should be at least 1");
	unsigned int tmp_k = (int) (0.5 + (((float) samp_count_ * det_freq) / samp_rate_));
	float tmp_coef = 2 * cos(((float) 2 * M_PI * tmp_k) / samp_count_);
	Bin newbin = {0, 0, tmp_coef, 0, mag_trig, 0, det_freq};
	bins_.push_back(newbin);
}

void Goertzel::RemoveBin(unsigned int det_freq){
	for(auto i = bins_.begin(); i != bins_.end(); i++){
		if(i->freq == det_freq){
			bins_.erase(i);
			return;
		}
	}
	throw std::invalid_argument("Bin not found");
}

void Goertzel::ProcessSample(float samp_value){
	for(auto i = bins_.begin(); i != bins_.end(); i++){
		float q0 = (i->coef * i->q1) - i->q2 + samp_value;
		i->q2 = i->q1;
		i->q1 = q0;
		if(++(i->samples_done) == samp_count_){
			i->last_mag = (i->q1 * i->q1) + (i->q2 * i->q2) - (i->coef * i->q1 * i->q2);
			i->samples_done = 0;
			i->q1 = 0;
			i->q2 = 0;
		}
	}
}

unsigned int Goertzel::LastMagValue(unsigned int freq){
	for(auto i = bins_.begin(); i != bins_.end(); i++){
		if(i->freq == freq)
			return i->last_mag;
	}
	throw std::invalid_argument("Bin not found");
}

bool Goertzel::LastMagTrig(unsigned int freq){
	for(auto i = bins_.begin(); i != bins_.end(); i++){
		if(i->freq == freq){
			if(i->last_mag > i->mag_trig)
				return true;
			return false;
		}
	}
	throw std::invalid_argument("Bin not found");
}

void Goertzel::ResetBins(void){
	for(auto i = bins_.begin(); i != bins_.end(); i++){
		i->last_mag = 0;
		i->samples_done = 0;
		i->q1 = 0;
		i->q2 = 0;
	}
}
