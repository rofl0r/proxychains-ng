'''
this will fix fuckin socket timout 
run this under su
'''


import os
import sys
from os import system


def install(rep):
  system('sudo apt-get install %s' % str(rep))
  
  
def uninstall(rep):
  system('sudo apt autoremove %s' % str(rep))
  
 
uninstall('tor')
install('tor')
