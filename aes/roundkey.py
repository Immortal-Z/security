#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2017, Jianping Zhao
#
# Licensed under the BSD 3-Clause License
# You may obtain a copy of the License at
# https://opensource.org/licenses/BSD-3-Clause

"""
This module is developed against the AddRoundKey step within the AES algorithm.

For more detail, please read the official AES document at: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

Functions:

round_key() -- perform XOR operation between matrix and key_block.
"""


def round_key(matrix, key_block):
    """
    This function is used for both AES encryption and AES decryption.

    The function will divide the matrix into four 4 bytes blocks (each column as a block), and perform XOR operation
    between block and key which contained in the key_block. At last, create and return the new matrix based on the
    XOR operation results.

    :param matrix: A 4x4 matrix which composed by 4 lists. The lists only accept numeric objects
    :param key_block: A list which contain four 4 byte keys.
    :return: A new matrix which be changed follow the AddRoundKey rule. The format of this matrix is same as the input
             matrix.
    """
    new_matrix = matrix.copy()
    position_tag = 0
    for key in key_block:
        column_value = 0
        for row in matrix:
            column_value = (column_value << 8) + row[position_tag]
        encrypted_column_value = column_value ^ key
        hexed_key = hex(encrypted_column_value)[2:].zfill(8)
        position_tag2 = 0
        for round_num in range(3):
            new_matrix[position_tag2][position_tag] = eval('0x' + hexed_key[:2])
            hexed_key = hexed_key[(-len(hexed_key)) + 2:]
            position_tag2 += 1
        new_matrix[position_tag2][position_tag] = eval('0x' + hexed_key[:2])
        position_tag += 1
    return new_matrix
