#!/usr/bin/env python

from gnuradio import gr
from gnuradio.extras import block_gateway
import numpy

BTDHT12EC_STATE_WAIT_PRE = 0
BTDHT12EC_STATE_WAIT_START = 1
BTDHT12EC_STATE_WAIT_BIT = 2
BTDHT12EC_STATE_WAIT_ZERO = 3
BTDHT12EC_STATE_WAIT_ONE = 4
BTDHT12EC_STATE_WAIT_END = 5

class bin_timing_decoder_ht12e_compat(gr.block):
  def __init__(self):
    gr.block.__init__(self, name="bin_timing_decoder_ht12e_compat", in_sig=[numpy.float32], out_sig=[numpy.int16])
    self.set_auto_consume(False)
    self.__state_reset()   

  def __state_reset(self):
    self.__cur_state = BTDHT12EC_STATE_WAIT_PRE
    self.__bits_recv = 0
    self.__cur_word = 0

  def __add_bit(self, bit_val):
    self.__cur_word >>= 1
    self.__cur_word |= 0b100000000000 if bit_val else 0
    self.__bits_recv += 1

  def work(self, input_items, output_items):
    if len(input_items[0]) == 0:
      return 0
    for cur_in_item in range(len(input_items[0])):
      if self.__cur_state == BTDHT12EC_STATE_WAIT_PRE:
        if input_items[0][cur_in_item] > 1e-3:
          self.__cur_state = BTDHT12EC_STATE_WAIT_START
      elif self.__cur_state == BTDHT12EC_STATE_WAIT_START:
        if 220e-6 < input_items[0][cur_in_item] < 450e-6:
          self.__cur_state = BTDHT12EC_STATE_WAIT_BIT
        else:
          self.__state_reset()
      elif self.__cur_state == BTDHT12EC_STATE_WAIT_BIT:
        if 220e-6 < input_items[0][cur_in_item] < 450e-6:
          self.__cur_state = BTDHT12EC_STATE_WAIT_ONE
        elif 550e-6 < input_items[0][cur_in_item] < 820e-6:
          self.__cur_state = BTDHT12EC_STATE_WAIT_ZERO
        else:
          self.__state_reset()
      elif self.__cur_state == BTDHT12EC_STATE_WAIT_ONE:
        if 550e-6 < input_items[0][cur_in_item] < 820e-6:
          self.__cur_state = BTDHT12EC_STATE_WAIT_BIT
          self.__add_bit(1)
        else:
          self.__state_reset()
      elif self.__cur_state == BTDHT12EC_STATE_WAIT_ZERO:
        if 220e-6 < input_items[0][cur_in_item] < 450e-6:
          self.__cur_state = BTDHT12EC_STATE_WAIT_BIT
          self.__add_bit(0)
        else:
          self.__state_reset()
      elif self.__cur_state == BTDHT12EC_STATE_WAIT_END:
        if input_items[0][cur_in_item] > 1e-3:
          #
          print("{0:0>12}".format(bin(self.__cur_word)[2:]))
          #
          output_items[0][0] = self.__cur_word
          self.consume(0, cur_in_item + 1)
          self.__state_reset()
          self.__cur_state = BTDHT12EC_STATE_WAIT_START
          return 1
        else:
          self.__state_reset()
          
      if self.__bits_recv == 12:
        self.__cur_state = BTDHT12EC_STATE_WAIT_END

    self.consume(0, cur_in_item + 1)
    return 0
