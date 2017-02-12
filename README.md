# burst-address.py

simple address creator for burst coin written in python

dependencies:
- curve25519-donna python wrapper available through 'pip'<br>
    https://pypi.python.org/pypi/curve25519-donna<br>
  (i looked for a simple pure python curve25519 but found none)

on linux installed by:<br>
sudo pip install curve25519-donna

if pip isn't on your system, debian based install of pip<br>
sudo apt-get install python-pip

execution by command line:
./burst-address.py "passphrase for account"<br>
or (if not set executable)<br>
python burst-address.py "passphrase for account"

spaces in passphrase are allowed by joining arugments list, providing as sign argument in quotes might be optimal

output will provide passphrase for account, long id (numeric address) for account and RS (reed-solomon) encoded address.

a note on public keys, first out going transaction on blockchain secures the public key for the account (burst wallet will provide message on accounts without public key). what this means is the account id (a 8 byte number) is known to have a certain curve25519 public key (a 32 byte number). notice the difference between the amount of possiblities, this indicates that a collision between a different key pair and the account can occur. registering a public key is the protection from that collision.

tested on linux using "Python 2.7.6" and "Python 3.6.0"<br>

written by damncourier in 2017<br>
released public domain

credit for code reuse would be nice<br>
donations would be nicer ;)<br>
BURST-PVSK-HNTX-FLAA-HTRSX
