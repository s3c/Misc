#!/usr/bin/env python

from gnuradio import gr
from gnuradio.extras import block_gateway
import numpy

class binary_level_to_timing(gr.block):
  def __init__(self, samp_rate):
    gr.block.__init__(self, name="binary_level_to_timing", in_sig=[numpy.int8], out_sig=[numpy.float32])
    self.set_auto_consume(False)
    self.__samp_rate = samp_rate
    self.__state_count = 0
    self.__state_high = False

  def work(self, input_items, output_items):
    if len(input_items[0]) == 0:
      return 0
    cur_out_item = 0
    for cur_in_item in range(len(input_items[0])):     
      if input_items[0][cur_in_item] == self.__state_high:
        self.__state_count += 1
      else:
        if cur_out_item == len(output_items[0]):
          break
        output_items[0][cur_out_item] = float(self.__state_count) / self.__samp_rate
        self.__state_count = 1
        self.__state_high = not self.__state_high
        cur_out_item += 1
    self.consume(0, cur_in_item + 1)
    return cur_out_item
