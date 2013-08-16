xFiSHpy
=======
FiSH/Mircryption clone for X-Chat in 100% Python3

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
- Python 3.2+
- XChat with Python3 support (e.g.: <a href="http://hexchat.github.io/downloads.html">HexChat 2.9.6</a>)
 
Install
=======
put "xFiSHpy" directory in "\<xchatdir\>/config/addons/"

Last done
=========
- * safety commit
- pickle tests
- import path fixed
- renamed to "xFiSHpy" to avoid same name with original
- re-version-ed to 1.0py_0.1 see above
- CBC default
- typo/grammar fix
- command alias added
- string-compares only after upper()