from subprocess import check_output
from json import loads
from shutil import copy, copy2



class Util

  @staticmethod
  def fileOut(file:str, data:str, mode='a') -> None: # mode 'a' stands for append, 'w' is overwrite and 'r' is read-pnly
    try:
      with open(file=file, mode=mode, encoding='UTF-8') as FILE:
        FILE.write(str(data))
    except Exception:
      print('fileOut error!')



'''
- Here is a detailed illustrated explanation of the Util.py file you provided 
  ideal for a university research assignment on surveillance/malware technology in Python.

                 📂 File: Util.py
                    ✅ Purpose

This utility class provides support functions that assist with:

- File I/O
- JSON parsing
- Shell command execution
- Data exfiltration (stealing files, logging shell output)
'''

'''




🔍 Code Breakdown

  🧱 Class: Util

    
  All nethods are @staticmethod, meaning they can be used 'without creating an  object' of the class
  



'''
