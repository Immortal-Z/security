#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2017, Jianping Zhao
#
# Licensed under the BSD 3-Clause License
# You may obtain a copy of the License at
# https://opensource.org/licenses/BSD-3-Clause

from aes.keyexpansion import generator
from aes.roundkey import round_key
from aes.subbytes import sub_bytes_inv
from aes.shiftrow import shift_row_inv
from aes.mixcolumns import mix_columns_inv


text = [[0x39, 0x02, 0xdc, 0x19],
        [0x25, 0xdc, 0x11, 0x6a],
        [0x84, 0x09, 0x85, 0x0b],
        [0x1d, 0xfb, 0x97, 0x32]]

initial_key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]

key_block = generator(initial_key)
key_block.reverse()
temp_key = key_block[:4]
temp_key.reverse()
temp_text = round_key(text, temp_key)
round_num = 1
key_num = 4
while round_num != 10:
    temp_key = key_block[key_num:key_num + 4]
    temp_key.reverse()
    temp_text = mix_columns_inv(round_key(sub_bytes_inv(shift_row_inv(temp_text)), temp_key))
    round_num += 1
    key_num += 4
else:
    temp_key = key_block[key_num:key_num + 4]
    temp_key.reverse()
    temp_text = round_key(sub_bytes_inv(shift_row_inv(temp_text)), temp_key)
decrypted_text = temp_text
