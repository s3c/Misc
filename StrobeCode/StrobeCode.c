/*
 * StrobeCode.c
 *
 * Created: 03.07.2013 12:58:35
 * Author: s3c
 * Purpose: Flashlight driver code for NANJG105, stock is an Attiny13 but this code was
 * written for the Attiny25 so a hardware mod is needed
 * Usage: To switch modes a flashlight needs to be turned on betwee 1 and 2 seconds 5 
 * times in a row, supported modes include: Constant, Strobe, SOS, Fade, Set Brightness Level
 */ 

//Todo: test this version, fix/determine BAT_LOW_VAL, disable PWM instead of setting OCR0B to zero?, does stateSG.curLvlC require volatile?

#include <avr/io.h>
#include <avr/eeprom.h>
#include <avr/interrupt.h>
#include <avr/power.h>
#include <avr/sleep.h>

#define EE_SIZE			128
#define EE_STR_SENT		0xEE

#define MODE_CONST		0
#define MODE_STROBE		1
#define MODE_SOS		2
#define MODE_FADE		3
#define MODE_SETLVL		4

#define STATE_PRE		0
#define STATE_CHANGE		1
#define STATE_DONE		2
#define STATE_BAT_LOW		3

#define SUBSTATE_MAX_VAL	4

#define PWM_MAX			125
#define PWM_STEP		25

#define BAT_LOW_VAL		440

//Holds all internal settings
struct{
	uint8_t curModeC; //Current flashlight mode
	uint8_t curSubmC; //Current submode, ie, presses to next mode up to SUBSTATE_MAX_VAL
	uint8_t *curEELocCP; //Current EEPROM location (start of current frame)
	volatile uint8_t curLvlC; //Current flashlight intensity up to PWM_MAX
	volatile uint16_t globalTimerIG; //Timer value used for mS timing, decremented each mS if non zero
	volatile uint8_t timeStateC; //State machine value
}stateSG;

//Save the current state to EEPROM, we use the fact that EEPROM index wraps around
//to save the data to a different location each time, this prolongs the EEPROM
//life, probably not needed but you never know. Write before erase to avoid 
//corruption flaws we were getting.
void saveState(void){
	eeprom_write_byte(stateSG.curEELocCP + 4, EE_STR_SENT);
	eeprom_write_byte(stateSG.curEELocCP + 5, stateSG.curModeC);
	eeprom_write_byte(stateSG.curEELocCP + 6, stateSG.curSubmC);
	eeprom_write_byte(stateSG.curEELocCP + 7, stateSG.curLvlC);
	eeprom_write_byte(stateSG.curEELocCP + 0, 0);
	eeprom_write_byte(stateSG.curEELocCP + 1, 0);
	eeprom_write_byte(stateSG.curEELocCP + 2, 0);
	eeprom_write_byte(stateSG.curEELocCP + 3, 0);
	stateSG.curEELocCP += 4;
}

//Load the state from EEPROM, use the wraparound again
void loadState(void){
	uint8_t *loopVarCP, curByteC;
	
	for(loopVarCP = 0; loopVarCP < (uint8_t *) EE_SIZE; loopVarCP++){
		curByteC = eeprom_read_byte(loopVarCP);
		if(curByteC == EE_STR_SENT){
			stateSG.curModeC = eeprom_read_byte(loopVarCP + 1);
			stateSG.curSubmC = eeprom_read_byte(loopVarCP + 2);
			stateSG.curLvlC = eeprom_read_byte(loopVarCP + 3);
			stateSG.curEELocCP = loopVarCP;
			if(!stateSG.curLvlC) //In case of corrupted EEPROM giving us nothing (can this still happen?)
				break;
			return;
		}
	}
	stateSG.curModeC = MODE_CONST;
	stateSG.curSubmC = 0;
	stateSG.curLvlC = PWM_MAX;
	stateSG.curEELocCP = 0;
}

//Advance state before saving to EEPROM
void nextState(void){
	stateSG.curSubmC++;
	if(stateSG.curSubmC > SUBSTATE_MAX_VAL){
		stateSG.curSubmC = 0;
		stateSG.curModeC++;
		if(stateSG.curModeC > MODE_SETLVL)
			stateSG.curModeC = MODE_CONST;
	}
}

//Revert state before saving to EEPROM
void preState(void){
	if(stateSG.curSubmC)
		stateSG.curSubmC = 0;
	else
		stateSG.curModeC--;
}

//Turns off ADC and go to sleep
void sleep(void){
	ADCSRA &= ~(1 << ADEN);
	set_sleep_mode(SLEEP_MODE_PWR_DOWN);
	sleep_enable();
	sleep_cpu();
}

//Delays x ms using ISR, just sits in a busy wait
void msDelay(uint16_t delayValI){
	stateSG.globalTimerIG = delayValI;
	while(stateSG.globalTimerIG);
}

//Fade in LED
void fadeIn(uint8_t fadeToC){
	uint8_t localCurLvlC = 0;
	
	while(localCurLvlC != fadeToC){
		OCR0B = localCurLvlC;
		msDelay(20);
		localCurLvlC++;
	}
}

//Fade out LED
void fadeOut(void){
	uint8_t localCurLvlC = stateSG.curLvlC;
	
	while(localCurLvlC){
		OCR0B = localCurLvlC;
		msDelay(20);
		localCurLvlC--;		
	}
}

//ISR triggers every 1mS, used to read the battery state, disable light on low battery,
//manage timers for other modes and manage the saving of states when the light
//has been turned on for certain lengths of time
ISR(TIM0_OVF_vect){
	static uint16_t modeTimeI = 1000;
	uint16_t curBatValC = ADC;

	if(stateSG.globalTimerIG)
		stateSG.globalTimerIG--;
	
	if(stateSG.timeStateC == STATE_BAT_LOW)
		return;
		
	if(curBatValC && curBatValC < BAT_LOW_VAL){
		stateSG.timeStateC = STATE_BAT_LOW;
		sei();
		fadeOut();
		sleep();
	}
	
	if(stateSG.timeStateC != STATE_DONE){
		modeTimeI--;
		if(!modeTimeI){
			if(stateSG.timeStateC == STATE_PRE){
				nextState();
				saveState();
				modeTimeI = 1000;
				stateSG.timeStateC = STATE_CHANGE;
			}else if(stateSG.timeStateC == STATE_CHANGE){
				preState();
				saveState();
				stateSG.timeStateC = STATE_DONE;
			}
		}
	}
}

//Loads the last state and sets up all peripherals
void setup(void){
	loadState();
	stateSG.timeStateC = STATE_PRE;
	
	//Setup Bridge Pins
	PORTB |= (1 << PB0) | (1 << PB3) | (1 << PB4); //Activate pull-ups for mode pins, not used atm
	
	//Setup Timer/PWM
	TCCR0A = (1 << COM0B1) | (1 << WGM01) | (1 << WGM00); //Fast PWM, OCR0A as Top, OCR0B sets duty, non inv
	TCCR0B = (1 << WGM02) | (1 << CS01) | (1 << CS00); //Prescaler set to 64
	OCR0A = PWM_MAX; //Gives 1000Hz (1ms) overflow ints for 8Mhz clock
	TIMSK = (1 << TOIE0); //Overflow int enable (TOV0)
	DDRB |= (1 << PB1); //Set PWM pin as output
	
	//Setup ADC
	ADMUX = (1 << REFS1) | (1 << MUX0); //Enable 1V reference, left adjust, set input to PB2
	ADCSRA = (1 << ADEN) | (1 << ADATE) | (1 << ADPS2) | (1 << ADPS1); //Enable ADC, set auto trigger, prescaler to 64
	ADCSRB = (1 << ADTS2); //Set auto trigger on timer overflow
	DIDR0 = (1 << ADC1D); //Digital input disable on PB2
	
	ADCSRA |= ADSC; //Do initial conversion
	while(ADCSRA & (1 << ADSC));
	ADCSRA |= ADSC; //First real value
	while(ADCSRA & (1 << ADSC));
	
	sei();
}

//Generate strobing sequence used for strobe+sos
void strobeGen(uint16_t highTimeC, uint16_t lowTimeC, uint8_t repCountC){
	uint8_t loopVarC;
	
	for(loopVarC = 0; loopVarC < repCountC; loopVarC++){
		OCR0B = stateSG.curLvlC;
		msDelay(highTimeC);
		OCR0B = 0;
		msDelay(lowTimeC);
	}
}

//Constant brightness mode
void modeConst(void){
	OCR0B = stateSG.curLvlC;
	while(1);
}

//Tactical strobe, 10Hz
void modeStrobe(void){
	while(1)
		strobeGen(50, 50, 255);
}

//Flashes SOS using strobing code
void modeSOS(void){
	while(1){
		strobeGen(200, 200, 3);
		msDelay(1000);
		strobeGen(600, 600, 3);
		msDelay(1000);
		strobeGen(200, 200, 3);
		msDelay(2000);
	}
}

//Fade in and out indef
void modeFade(void){
	uint8_t origLvlC = stateSG.curLvlC;
	
	while(1){
		fadeOut();
		fadeIn(origLvlC);
	}
}

//Allows setting the brithness for all other modes, 5 brightness steps
void modeSetLvl(void){
	stateSG.timeStateC = STATE_DONE;
	stateSG.curModeC = MODE_CONST;
	
	while(1){
		for(stateSG.curLvlC = PWM_STEP; stateSG.curLvlC <= PWM_MAX; stateSG.curLvlC += PWM_STEP){
			OCR0B = stateSG.curLvlC;
			saveState();
			msDelay(2000);
		}
	}
}

//Load all settings, initialize hardware and dispatch mode
int main(void){
	setup();
	
	switch(stateSG.curModeC){
		case(MODE_CONST): modeConst();
		case(MODE_STROBE): modeStrobe();
		case(MODE_SOS): modeSOS();
		case(MODE_FADE): modeFade();
		case(MODE_SETLVL): modeSetLvl();
	}
	
	return 0;
}
