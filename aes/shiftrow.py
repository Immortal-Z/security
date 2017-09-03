#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2017, Jianping Zhao
#
# Licensed under the BSD 3-Clause License
# You may obtain a copy of the License at
# https://opensource.org/licenses/BSD-3-Clause

"""
This module is developed against the ShiftRow step within the AES algorithm.

The module support the functionality for both ShiftRow and Inverse ShiftRow. For more detail, please read the official
AES document at: http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

Functions:

shitf_row() -- return a matrix which be adjusted row by row.
shitf_row_inv() -- return a matrix which be adjusted row by row inversely.
"""


def shift_row(matrix):
    """
    This function is used for AES encryption. The first row is unchanged; The bytes in second, third and forth row are
    shifted over one, two and three bytes to the left respectively.

    :param matrix: A 4x4 matrix which composed by 4 lists. The lists only accept numeric objects.
    :return: A new matrix which be changed follow the ShiftRow rule. The format of this matrix is same as the input
             matrix.
    """
    new_matrix = [matrix[0], [], [], []]
    row_num_offset = -1
    for row in matrix[1:]:
        position_tag = -4
        new_row = row.copy()
        for byte in row:
            new_row[position_tag + 4 + row_num_offset] = byte
            position_tag += 1
        new_matrix[position_tag - row_num_offset] = new_row
        row_num_offset -= 1
    return new_matrix


def shift_row_inv(matrix):
    """
    This function is used for AES decryption. The first row is unchanged; The bytes in second, third and forth row are
    shifted over one, two and three bytes to the right respectively.

    :param matrix: A 4x4 matrix which composed by 4 lists. The lists only accept numeric objects.
    :return: A new matrix which be changed follow the Inverse ShiftRow rule. The format of this matrix is same as
    the input matrix.
    """
    new_matrix = [matrix[0], [], [], []]
    matrix.reverse()
    row_num_offset = -1
    for row in matrix[:3]:
        position_tag = -4
        new_row = row.copy()
        for byte in row:
            new_row[position_tag + 4 + row_num_offset] = byte
            position_tag += 1
        new_matrix[row_num_offset] = new_row
        row_num_offset -= 1
    return new_matrix
