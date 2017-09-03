#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2017, Jianping Zhao
#
# Licensed under the BSD 3-Clause License
# You may obtain a copy of the License at
# https://opensource.org/licenses/BSD-3-Clause

from random import getrandbits
from random import randint

p = getrandbits(128)
g = randint(20, 100)
a = getrandbits(2048)
b = getrandbits(2048)
A = pow(g, a, p)
B = pow(g, b, p)
key = pow(A, b, p)
