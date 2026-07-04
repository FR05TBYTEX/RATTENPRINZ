placeholder for now

writing this down so i dont forget - 
chose NOT to go with ECDHKE because it would require cryptography on both ends, and revshell.py is supposed to be lightweight and more importantly should only use default python packages so that it works on all systems where python is installed.
WRT DHKE it was possible but it took way too long to generate keys (sometimes quite quickly but often 2-3+ seconds) which annoyed me and went against the 'lightweight' and 'fast' design philosophy
