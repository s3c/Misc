#ifndef Goertzel_h
#define Goertzel_h

#include <vector>

class Goertzel {
	private:
		struct Bin {
			float q1, q2, coef, last_mag, mag_trig;
			unsigned int samples_done, freq;
		};
		std::vector<Bin> bins_;
		unsigned int samp_rate_;
		unsigned int samp_count_;
	public:
		Goertzel(unsigned int set_samp_rate, unsigned int set_samp_count);
		void AddBin(unsigned int det_freq, float mag_trig = 0);
		void RemoveBin(unsigned int det_freq);
		void ProcessSample(float samp_value);
		unsigned int LastMagValue(unsigned int freq);
		bool LastMagTrig(unsigned int freq);
		void ResetBins(void);
};

#endif
