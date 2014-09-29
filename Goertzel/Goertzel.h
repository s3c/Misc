#ifndef Goertzel_h
#define Goertzel_h

#include <vector>

class Goertzel {
	private:
		struct Bin {
			float q1, q2, coef, freq, last_mag, mag_trig;
			unsigned int samples_done;
		};
		std::vector<Bin> bins_;
		float samp_freq_;
		unsigned int samp_count_;
	public:
		Goertzel(float set_samp_freq, unsigned int set_samp_count);
		void AddBin(float det_freq, float mag_trig = 0);
		void RemoveBin(float det_freq);
		void ProcessSample(float samp_value);
		unsigned int LastMagValue(float freq);
		bool LastMagTrig(float freq);
		void ResetBins(void);
};

#endif
