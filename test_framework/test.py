from unittest.case import SkipTest
import sys
sys.path.insert(0, '../')

from test_vm import test_datafiles
from test_vm import check_datafile

# for x in test_datafiles():
#     try:
#         x[0](*x[1:])
#     except SkipTest as s:
#         print('Skip:', s)
#         continue
#

try:
    check_datafile('maps/simple.data')
except SkipTest as s:
    print('Skip:', s)

