#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2017, Jianping Zhao
#
# Licensed under the BSD 3-Clause License
# You may obtain a copy of the License at
# https://opensource.org/licenses/BSD-3-Clause

"""
This module is used to generate the key for AddRoundKey step within the AES algorithm.

For more detail, please read the official AES document at: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

Functions:

rotate_key() -- the bytes of the input are shifted over one bytes to the left.
sub_bytes_key() -- the bytes of the input are replaced by the value within the s_box.
generator() -- creates 40 keys used in AddRoundKey step.
"""


def rotate_key(temp_key):
    """
    This function is used to adjust the byte position in the temp_key, the bytes of the temp_key are shifted over one
    bytes to the left.

    :param temp_key: A 4 bytes value, only accept numeric object.
    :return: A new 4 bytes value.
    """
    hexed_key = hex(temp_key)[2:].zfill(8)
    decomposed_key = []
    for round_num in range(3):
        decomposed_key.append(eval('0x' + hexed_key[:2]))
        hexed_key = hexed_key[(-len(hexed_key)) + 2:]
    decomposed_key.append(eval('0x' + hexed_key[:2]))
    rotated_key = decomposed_key.copy()
    position_tag = -4
    for byte in decomposed_key:
        rotated_key[position_tag + 3] = byte
        position_tag += 1
    return rotated_key


def sub_bytes_key(rotated_key):
    """
    This function is used to replace the bytes in the rotated_key with the new value which from the s_box.

    :param rotated_key: A 4 bytes value, only accept numeric object.
    :return: A new 4 bytes value.
    """
    s_box = [[0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
             [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
             [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
             [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
             [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
             [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
             [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
             [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
             [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
             [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
             [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
             [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
             [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
             [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
             [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
             [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]]
    substituted_key_part = []
    for byte in rotated_key:
        row_num = eval('0x' + (hex(byte)[2:].zfill(2))[0])
        column_num = eval('0x' + (hex(byte)[2:].zfill(2))[-1])
        new_byte = s_box[row_num][column_num]
        substituted_key_part.append(new_byte)
    substituted_key = 0
    for part in substituted_key_part:
        substituted_key = (substituted_key << 8) + part
    return substituted_key


def generator(initial_key):
    """
    This function is used to creates 40 keys based on the initial key. The detail is showing below:

    Assuming the initial keys are W[0]-W[3], and expended new keys are W[4]-W[43]:
    1) If i % 4 is not equal to 0
        a. Using rotate_key() function to handle the W[i-1].
        b. Using sub_bytes_key() function to handle the result of the step a.
        c. Perform XOR operation between the result of the step b and one value in the rcon_table.
        d. Perform XOR operation between the result of the step c and W[i-4].
        e. The result of the step d is the new key.
    2) If i % 4 is equal to 0
        a. Perform XOR operation between W[i-1] and W[i-4].
        b. The result of the step a is the new key.

    :param initial_key: The first 4 keys assigned by the user.
    :return: A list contains 44 keys.
    """
    rcon_table = [0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
                  0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000]
    # Format the initial key
    key_segment = []
    counter = 0
    segment = 0
    for byte in initial_key:
        if counter != 4:
            segment = (segment << 8) + byte
            counter += 1
        else:
            key_segment.append(segment)
            segment = byte
            counter = 1
    key_segment.append(segment)
    # Generate new keys
    rcon_counter = 0
    for key_counter in range(4, 44):
        if key_counter % 4 == 0:
            temp_key = key_segment[key_counter - 1]
            temp_key = rotate_key(temp_key)
            temp_key = sub_bytes_key(temp_key)
            temp_key = rcon_table[rcon_counter] ^ temp_key
            new_key = temp_key ^ key_segment[key_counter - 4]
            key_segment.append(new_key)
            rcon_counter += 1
        else:
            new_key = key_segment[key_counter - 4] ^ key_segment[key_counter - 1]
            key_segment.append(new_key)
    return key_segment
