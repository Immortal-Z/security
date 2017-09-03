#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2017, Jianping Zhao
#
# Licensed under the BSD 3-Clause License
# You may obtain a copy of the License at
# https://opensource.org/licenses/BSD-3-Clause

from aes.keyexpansion import generator
from aes.roundkey import round_key
from aes.subbytes import sub_bytes
from aes.shiftrow import shift_row
from aes.mixcolumns import mix_columns

text = [[0x32, 0x88, 0x31, 0xe0],
        [0x43, 0x5a, 0x31, 0x37],
        [0xf6, 0x30, 0x98, 0x07],
        [0xa8, 0x8d, 0xa2, 0x34]]

initial_key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]
key_block = generator(initial_key)

temp_text = round_key(text, (key_block[:4]))
round_num = 1
key_num = 4
while round_num != 10:
    temp_text = round_key(mix_columns(shift_row(sub_bytes(temp_text))), key_block[key_num:key_num + 4])
    round_num += 1
    key_num += 4
else:
    temp_text = round_key(shift_row(sub_bytes(temp_text)), key_block[key_num:key_num + 4])
encrypted_text = temp_text
