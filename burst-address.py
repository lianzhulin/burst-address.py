#!/usr/bin/env python

# burst-address.py
# a burst address generator in python
#
# execution requires installation of curve25519-donna (https://pypi.python.org/pypi/curve25519-donna)
# example of installation on linux "sudo pip install curve25519-donna"
#
# test on linux using "Python 2.7.6" and "Python 3.6.0"
#
# written by damncourier in 2017
# released public domain
#
# credit for code reuse would be nice
# donations would be nicer ;)
# BURST-PVSK-HNTX-FLAA-HTRSX

####### import libraries
# access to command line arguments
import sys, argparse;

# sha2 256 digest function
from hashlib import sha256;

# curve25519-donna available from pip
# Private to set private key
from curve25519 import Private;

from binascii import hexlify;

###### support python 2 and 3

# over ride long with int
if sys.version_info > (3,):
    long = int;

###### class definition

# ReedSolomon class (incomplete only encoding)
# ported from java:
# https://github.com/burst-team/burstcoin/blob/master/src/java/nxt/crypto/ReedSolomon.java
class ReedSolomon:
    initial_codeword = [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    gexp = [1, 2, 4, 8, 16, 5, 10, 20, 13, 26, 17, 7, 14, 28, 29, 31, 27, 19, 3, 6, 12, 24, 21, 15, 30, 25, 23, 11, 22, 9, 18, 1];
    glog = [0, 0, 1, 18, 2, 5, 19, 11, 3, 29, 6, 27, 20, 8, 12, 23, 4, 10, 30, 17, 7, 22, 28, 26, 21, 25, 9, 16, 13, 14, 24, 15];
    codeword_map = [3, 2, 1, 0, 7, 6, 5, 4, 13, 14, 15, 16, 12, 8, 9, 10, 11];
    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

    base_32_length = 13;
    base_10_length = 20;

    def encode(self, plain):
        plain_string = str(plain);
        length = len(plain_string);
        plain_string_10 = [0]*20;
        for i in range(length):
            plain_string_10[i] = ord(plain_string[i]) - ord('0');

        codeword_length = 0;
        codeword = [0]*len(self.initial_codeword);

        while True: # emulating do ... while from java
            new_length = 0;
            digit_32 = 0;
            for i in range(length):
                digit_32 = digit_32 * 10 + plain_string_10[i];
                if digit_32 >= 32:
                    plain_string_10[new_length] = digit_32 >> 5;
                    digit_32 &= 31;
                    new_length += 1;
                elif new_length > 0:
                    plain_string_10[new_length] = 0;
                    new_length += 1;
            length = new_length;
            codeword[codeword_length] = digit_32;
            codeword_length += 1;
            if not length > 0:
                break;

        p = [0, 0, 0, 0];
        for i in range(self.base_32_length - 1, -1, -1):
            fb = codeword[i] ^ p[3];
            p[3] = p[2] ^ self.gmult(30, fb);
            p[2] = p[1] ^ self.gmult(6, fb);
            p[1] = p[0] ^ self.gmult(9, fb);
            p[0] =        self.gmult(17, fb);

        codeword[self.base_32_length:] = p[:];

        cypher_string = "";
        for i in range(17):
            codework_index = self.codeword_map[i];
            alphabet_index = codeword[codework_index];
            cypher_string += self.alphabet[alphabet_index];

            if (i & 3) == 3 and i < 13:
                cypher_string += '-';

        return cypher_string;

    def decode(self, cypher_string):

        codeword = [0]*len(ReedSolomon.initial_codeword);
        codeword = self.initial_codeword;

        codeword_length = 0;
        for i in range(len(cypher_string)):
            position_in_alphabet = self.alphabet.find(cypher_string[i]);

            if (position_in_alphabet <= -1 or position_in_alphabet > len(self.alphabet)):
                continue;

            codework_index = self.codeword_map[codeword_length];
            codeword[codework_index] = position_in_alphabet;
            codeword_length += 1;

        length = self.base_32_length;
        cypher_string_32 = [0]*length;
        for i in range(length):
            cypher_string_32[i] = codeword[length - i - 1];

        plain_string_builder = '';
        while True: #// base 32 to base 10 conversion
            new_length = 0;
            digit_10 = 0;

            for i in range(length):
                digit_10 = digit_10 * 32 + cypher_string_32[i];

                if digit_10 >= 10:
                    cypher_string_32[new_length] = int(digit_10 / 10);
                    digit_10 %= 10;
                    new_length += 1;
                elif new_length > 0:
                    cypher_string_32[new_length] = 0;
                    new_length += 1;

            length = new_length;
            plain_string_builder += chr(digit_10 + ord('0'));
            if not length > 0:
                break;

        bigInt = int(plain_string_builder[::-1]);
        return bigInt;

    def gmult(self, a, b):
        if a == 0 or b == 0:
            return 0;

        idx = (self.glog[a] + self.glog[b]) % 31;

        return self.gexp[idx];

def convert():
    rs = ReedSolomon();
    if args.account.count('-') > 1:
        args.address = args.account if len(args.account) <= 20 else args.account[6:] 
        args.number_id = rs.decode(args.address)
        args.long_id = args.number_id if args.number_id < 2**63 else args.number_id - 2**64
    else:
        account = int(args.account)
        if account < 0:
            args.number_id = account + 2**64
            args.long_id = account
        elif account > 2**63-1:
            args.number_id = account
            args.long_id = account - 2**64
        else:
            args.number_id = args.long_id = account
        args.address = rs.encode(args.number_id)
    print(args)

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("-a", "--account", help="account id or address")
    parser.add_argument('passphrase', nargs='*', help='account passphrase')
    args = parser.parse_args()
    if args.account:
        convert() or exit()

####### check for arguments and print usage
if len(sys.argv) < 2:
    sys.exit("please supply passphrase as command line argument");

###### handle passphrase

# drop argv[0] (script file name) and join rest with spaces
#del sys.argv[0];
passphrase = " ".join(args.passphrase);

# print passphrase inside double quotes
print("Passphrase = \"%s\""%(passphrase));

###### get long id for account

# private key from passphrase
private = sha256(passphrase.encode('utf-8')).digest();

# public key from curve25519
curve = Private(secret=private);
public = curve.get_public();
print("Private key", hexlify(curve.serialize()))
print("Public key", hexlify(public.serialize()))

# hash public key
hashdress = sha256(public.serialize()).digest();

# hash slice 0..7, endswith 13
hashdress = b'\x0D' + hashdress[0:]

# create long id from hash
address = long(0);
i = 7;
while i>=0:
    placevalue = pow(256,i);
    try: # python 2 give character
        bytesum = ord(hashdress[i]) * placevalue;
    except TypeError: # python 3 gives int
        bytesum = hashdress[i] * placevalue;
    address += bytesum;
    i-=1;

# print long id and account number id
print("Long id = \"%s\""%(address if address <= 2**63-1 else address - 2**64));

print("Number id = \"%s\""%(address));

###### get reed-solomon for account

# object instantiation
rs = ReedSolomon();

print("RS id = \"BURST-%s\""%rs.encode(address));
