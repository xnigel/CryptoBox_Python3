# CryptoBox 
CryptoBox is a cryptographical tool with GUI being used for encrypting and decrypting via multibple algorithms, including DES, TDES, AES, RSA. 
Hash calculator, XOR, and random number generators are also upported by CryptoBox.

# Essential libraries
To execute the CryptBox, a bunch of Python libraries need to be installed. Follow the commands below to get it done.

If the old version of pycrypto / crypto was installed, uninstall them:
>pip3 uninstall pycrypto

>pip3 uninstall crypto

Install new pip / pycrypto / pyOpenSSL
>python.exe -m pip install --upgrade pip

>pip3 install pycryptodome

>pip3 install pyOpenSSL


# Exceute CryptoBox
<img src="https://github.com/xnigel/CryptoBox_Python3/blob/main/GUI_demo_1_DES.png" width =250> <img src="https://github.com/xnigel/CryptoBox_Python3/blob/main/GUI_demo_2_TDES.png" width =250> <img src="https://github.com/xnigel/CryptoBox_Python3/blob/main/GUI_demo_3_AES.png" width =250>

# Version history
DES operation works very well on v00.09.09.x 201610xx
v00.09.09 has been added new buttons:
01. TDES algorithm has been added !!! Works well !!!
02. AES  algorithm has been added !!! Works well !!!
03. Random number generator has been added !!! Works well !!!
04. Added a Exit button to quit program !!! Works well !!!
05. Added algo_tab (x6). SHA and RSA are not completed xxx - (RSA is not correct - 20161219)
    RSA calculation is correct - 20170301
06. Adding the menu bar
07. DES/TDES function is corrected !!!
08. Adding length counter after key and iv fileds
09. Adding fileopen function for RSA key-file and data-file import
10. Adding Hash function and GUI...........all done except HMAC operation
11. Scrollbar has not been added due to lack of knowledge............
12. Incorrect key length error message is removed in DES/TDES - solved!!!
13. "Use output as the key" function is added!!!
14. Correct all fonts !!!
15. Digital clock and counter for 120PIN have been completed !!!
16. RSA datainput and dataoutput text box works well !!!
17. RSA calculation is fully solved !!!!!!! 20170301
18. David gave me a suggestion on using RSA.construct((n, e, d)) to import keys
19. RSA.construct() is being used correctly!!! 20170301
20. Code migration from Python2 to Python3 20230825 - v02.01.01
21. Correcting the functionalities in the Python3 code 20230919 - v02.01.02
22. Released final version - v02.02.00
23. Adding new files hasing - v02.03.xx - from 2024.10.25
24. Adding password generator - v02.04.01 - Done on 2025.05.28