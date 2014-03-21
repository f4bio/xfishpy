STATUS
======
NOT WORKING! WORKING ON FIX AS SOON AS I GOT SOME SPARE TIME!

xFiSHpy
=======
FiSH/Mircryption clone for (He)XChat in 100% Python3

Credits
=======
All credits to:<br />
http://forum.vithon.org/Thread/show/54/FiSH_encryption_for_X_Chat_Python.html<br />
<br />
I just refactored and fixed the code to work with Python3

Info
====
Requirements:<br />
- PyCrypto 2.6+
- Python 3.3+
- XChat with Python3 support (e.g.: <a href="http://hexchat.github.io/downloads.html">HexChat 2.9.6</a>)
 
Install
=======
linux:<br />
- put/link "xfish.py" in "\<[he]xchatdir\>/config/addons/"
- put/link "irccrypt.py" in /usr/lib/python3.3/

Last done
=========
- * safety commit
- pickle tests
- import path fixed
- renamed to "xFiSHpy" to avoid same name as original
- re-version-ed to 1.0py_0.1 see above
- CBC default
- typo/grammar fix
- command alias added
- string-compares only after upper()