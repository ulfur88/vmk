import subprocess





if __name__ == '__main__':
    print("Unmounting Encrypted drive")

    subprocess.run(['sudo', 'umount', "/mnt/ntfs"], stdout=subprocess.PIPE)
    subprocess.run(['sudo', 'umount', "/mnt/bitlocker"], stdout=subprocess.PIPE)

    print("Drives unmounted")

