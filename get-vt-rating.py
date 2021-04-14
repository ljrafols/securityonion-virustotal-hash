"""
Name: Get VT Rating
Author: Loyd Rafols (ljrafols/lessigen)
Date Created: Apr 6, 2021
Date Modified: Apr 13, 2021

Reqs: gcc and python3-devel (yum install gcc python3-devel), aiohttp (python3 -m pip install aiohttp)

Licensed under the GNU General Public License Version 3 (GNU GPL v3),
    available at: https://www.gnu.org/licenses/gpl-3.0.txt

vt-py library is licensed under Apache License 2.0, see LICENSE for more info
"""

import os
import time
import hashlib
import vt


def main():
    # Change this dir string to the directory of the extracted files
    directory = os.fsencode("/nsm/zeek/extracted/complete")

    for file in os.listdir(directory):
        path = os.path.join(directory, file)
        
        if os.path.isdir(path):
            pass        # skip other subdirectories
        else:
            filename = os.fsdecode(path)
            md5hash = retrieve_file_hash(filename)

            vt_result = query_vt_api(md5hash)       # query VT API using hash
            is_hash_malicious(vt_result, filename, md5hash)
            
def retrieve_file_hash(filename):
    """Reads a given file's (filename) contents and generates an MD5 hash.
    
    Returns the MD5 hash of the file as a string.
    """

    with open(filename, "rb") as f:
        exe_bytes = f.read()
        md5hash = hashlib.md5(exe_bytes).hexdigest()
        f.close()

    return md5hash

def query_vt_api(md5hash):
    """Queries the VirusTotal API using a file's hash (md5hash).
    
    Returns the vt_result variable as an Object.
    """

    # ENTER YOUR API KEY BELOW
    vt_api = vt.Client("<YOUR-API-KEY-HERE>")
    vt_result = vt_api.get_object("/files/{hash}".format(hash = md5hash))
    vt_api.close()

    return vt_result

def is_hash_malicious(vt_result, filename, md5hash):
    """Determines if a hash submitted to VirusTotal is malicious or not.
    Currently set for a minimum of 10 AV engines to have detected the sample as "malicious".
    Logs resultant filename and hash into "virustotal.log" in the CWD, along with their determined maliciousness.

    Does not return anything.
    """
    malicious_count = vt_result.last_analysis_stats.get("malicious")      # get number of malicious matches

    with open("virustotal.log", "a") as vt_log:     # write result to virustotal.log file
        if (malicious_count >= 10):       # tune for individual taste
            vt_log.write("!! ALERT !! - VirusTotal determined this file and hash to be malicious --\nFilename: " +
                filename + ";\nHash: "+ md5hash + "\n")
            print("!! ALERT !! - VirusTotal determined this file and hash to be malicious: " 
                + filename + "; " + md5hash)

        else:
            vt_log.write("Following file was not detected as malicious by VirusTotal --\nFilename: " +
                filename + ";\nHash: "+ md5hash + "\n")
            print("Not malicious: " + filename + "; " + md5hash)
        
        vt_log.close()

    # poor boi can't afford VT premium API :(
    # mitigate likelihood of VT API rate limiting
    time.sleep(15) 

if __name__ == '__main__':
    main()