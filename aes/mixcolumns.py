#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2017, Jianping Zhao
#
# Licensed under the BSD 3-Clause License
# You may obtain a copy of the License at
# https://opensource.org/licenses/BSD-3-Clause

"""
This module is developed against the MixColumns step within the AES algorithm.

The module support the functionality for both MixColumns and Inverse MixColumns. For more detail, please read the
official AES document at: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

Functions:

multiply() -- perform finite field multiplication and return a decimal integer as the result.
mix_columns() -- return a matrix which handled by MixColumn algorithm.
mix_columns_inv() -- return a matrix which handled by Inverse MixColumn algorithm.
"""


def multiply(number_1, number_2):
    """
    This function is used to perform finite field multiplication, which is the core operation of the MixColumn step.

    :param number_1: The first number which involve the multiplication.
    :param number_2: The second number which involve the multiplication.
    :return: A decimal integer
    """
    result_list = [number_1]
    for x in range(7):
        if number_1 >= 0x80:
            result = ((number_1 << 1) & 0xff) ^ 0x1b
            result_list.append(result)
            number_1 = result
        else:
            result = number_1 << 1
            result_list.append(result)
            number_1 = result
    result_list.reverse()
    final_result = 0
    zipper = zip('{:08b}'.format(number_2), result_list)
    for x in zipper:
        if int(x[0]) != 0:
            final_result ^= x[1]
        else:
            pass
    return final_result


def mix_columns(input_matrix):
    """
    This function is used for AES encryption. The input matrix will perform special matrix multiplication with the
    constant_matrix which indicated below, and return a new matrix. For the detail about calculation algorithm, please
    read the official AES document at: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

    :param input_matrix: A 4x4 matrix which composed by 4 lists. The lists only accept numeric objects.
    :return: A new matrix which be changed follow the MixColumn rule. The format of this matrix is same as the
             input matrix.
    """
    constant_matrix = [[0x02, 0x03, 0x01, 0x01],
                       [0x01, 0x02, 0x03, 0x01],
                       [0x01, 0x01, 0x02, 0x03],
                       [0x03, 0x01, 0x01, 0x02]]
    new_matrix = [[], [], [], []]
    zipped_matrix = zip(constant_matrix, input_matrix)
    position_tag_1 = 0  # Indicates the byte position of current row within the input_matrix.
    position_tag_2 = 0  # Indicates the byte position of current row within the constant_matrix.
    byte_counter = 0    # Indicates the byte number of current row within the new_matrix.
    position_tag_3 = 0  # Indicate the current row position within the new_matrix.
    for item in zipped_matrix:
        for byte in item[1]:
            new_byte = 0x00
            for row in input_matrix:
                new_byte ^= multiply(row[position_tag_1], item[0][position_tag_2])
                position_tag_2 += 1
            if byte_counter < 4:
                new_matrix[position_tag_3].append(new_byte)
                byte_counter += 1
            else:
                position_tag_3 += 1
                byte_counter = 1
                new_matrix[position_tag_3].append(new_byte)
            position_tag_2 = 0
            position_tag_1 += 1
        position_tag_1 = 0
    return new_matrix


def mix_columns_inv(input_matrix):
    """
    This function is used for AES decryption. The input matrix will perform special matrix multiplication with the
    constant_matrix which indicated below, and return a new matrix. For the detail about calculation algorithm, please
    read the official AES document at: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

    :param input_matrix: A 4x4 matrix which composed by 4 lists. The lists only accept numeric objects.
    :return: A new matrix which be changed follow the Inverse MixColumn rule. The format of this matrix is same as the
             input matrix.
    """
    constant_matrix = [[0x0e, 0x0b, 0x0d, 0x09],
                       [0x09, 0x0e, 0x0b, 0x0d],
                       [0x0d, 0x09, 0x0e, 0x0b],
                       [0x0b, 0x0d, 0x09, 0x0e]]
    new_matrix = [[], [], [], []]
    zipped_matrix = zip(constant_matrix, input_matrix)
    position_tag_1 = 0  # Indicates the byte position of current row within the input_matrix.
    position_tag_2 = 0  # Indicates the byte position of current row within the constant_matrix.
    byte_counter = 0    # Indicates the byte number of current row within the new_matrix.
    position_tag_3 = 0  # Indicate the current row position within the new_matrix.
    for item in zipped_matrix:
        for byte in item[1]:
            new_byte = 0x00
            for row in input_matrix:
                new_byte ^= multiply(row[position_tag_1], item[0][position_tag_2])
                position_tag_2 += 1
            if byte_counter < 4:
                new_matrix[position_tag_3].append(new_byte)
                byte_counter += 1
            else:
                position_tag_3 += 1
                byte_counter = 1
                new_matrix[position_tag_3].append(new_byte)
            position_tag_2 = 0
            position_tag_1 += 1
        position_tag_1 = 0
    return new_matrix
