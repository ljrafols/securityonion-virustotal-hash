# Security Onion - VirusTotal API integration script (get-vt-rating)

get-vt-rating is a Python script that creates alerts based on stats provided by the VirusTotal API. This script is intended to assist security analysts in providing actionable intelligence towards incidents, by actively leveraging VirusTotal and its partners in finding new threats that have emerged, that have possibly bypassed an IDS' ruleset due to missing signatures. This will help in creating signatures to mitigate further attacks by new variants of malware.

# Script Description

The script iteratively loops through all files extracted by Zeek (by default, it checks the default SO extracted directory at `/nsm/zeek/extracted/`). Each file that is encountered has an MD5 hash generated and submitted to the VirusTotal API. The results from the API request are used to determine if a file is malicious or not (this is currently set to at least 10 AV engines resulting in "malicious"). In the current iteration, it only logs to the console and to the "`virustotal.log`" file in the CWD, but I plan on integrating it into Security Onion's Alerts dashboard.

To test this script, I have provided 5 malware samples in the `malware-samples/` directory, courtesy of dasmalwerk.eu:
- **Gen:Variant.Johnnie.97338** (240387329dee4f03f98a89a2feff9bf30dcba61fcf614cdac24129da54442762.zip)
- **Trojan.GenericKD.40436037** (785872bbef35d86fe6ce8a53be29995cfd0f251d2a171145bd6685bebe63ebc8.zip)
- **'Adware ( 004f7c2e1 )** (37ea273266aa2d28430194fca27849170d609d338abc9c6c43c4e6be1bcf51f9.zip)
- **Trojan.Delf.Agent.HZ** (bf34c8ed9467299cb2c7d711e63ab460e4039d5355ef76eb1d5c73b51b0ef637.zip)
- **Gen:Heur.PonyStealer.2** (42154d0805933548da9b7a9fbbce40be9e155091e6f96ed4ce324c21b3430b20.zip)

One **non-malicious** executable was also tested to verify that the script would not incorrectly classify malicious executables; it was not included in this repo. It is the `firefox.exe` executable from a standard **Mozilla Firefox 87.0 (64-bit)** installation.

Tested and working on Security Onion 2.3.40. 

# Usage
`python get-vt-rating.py`

# Requirements
- Security Onion 2.3.40
- aiohttp (installed automatically through requirements.txt or install manually via "pip install aiohttp")
- gcc, python3-devel (yum install gcc python3-devel)

# License
Licensed under GNU GPL v3, found at https://www.gnu.org/licenses/gpl-3.0.txt.

[VirusTotal/vt-py](https://github.com/VirusTotal/vt-py/blob/master/LICENSE): Apache License 2.0
