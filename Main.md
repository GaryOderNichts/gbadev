# Introduction #

Development Environment:
In order to compile binaries for Wii/vWii, you must have devkitPro (including devkitPPC and devkitARM) installed on your system. Personally, Linux is my preference for development, so I'll outline the development steps for that here.

1. Create a new user to be used for development, mine is called 'wii', with a home directory of /home/wii.

2. Download download devkitARMupdate.pl and devkitARMupdate.pl from http://sourceforge.net/projects/devkitpro/files/Automated%20Installer/ and  Place these in your home directory.

3. From the shell/terminal set the executable bits on these scripts. 'chmod +x devkit**'**

4. Execute devkitPPCupdate.pl. The script will now download the base packages for devkitPPC.

```
./devkitPPCupdate.pl
```

5. Execute devkitARMupdate.pl. The script will now download the base packages for devkitARM.
```
./devkitARMupdate.pl
```

6. These scripts do not download zlib (compression library) automatically, so grab zlib-1.2.5-ppc.tar.bz2 AND zlib-1.2.5-arm.tar.gz from http://sourceforge.net/projects/devkitpro/files/portlibs/ppc/ AND http://sourceforge.net/projects/devkitpro/files/portlibs/arm/ respectively. Place them in your home directory (/home/wii/devkitPPC, and /home/wii/devkitARM, respectively.)

7. Time to extract -
```
cd ~/devkitPro/devkitPPC ; tar -jxvf zlib-1.2.5-ppc.tar.bz2 ; cd ~/devkitPro/devkitARM ; tar -jxvf zlib-1.2.5-arm.tar.bz2
```

8. Set your environment variables:
```
export DEVKITPRO=$HOME/devkitPro
export DEVKITPPC=$DEVKITPRO/devkitPPC
export DEVKITARM=$DEVKITPRO/devkitARM`
```

9. Test by doing 'ls -la $DEVKITPRO'. You should see something similar to this:

```
wii@tal-linux:~$ ls -la $DEVKITPRO
total 44
drwxr-xr-x  9 wii wii 4096 May 21 10:27 .
drwxr-xr-x 14 wii wii 4096 May 22 16:32 ..
lrwxrwxrwx  1 wii wii   14 May 21 10:27 bin -> devkitARM/bin/
drwxr-xr-x  8 wii wii 4096 May 22 10:44 devkitARM
drwxr-xr-x  9 wii wii 4096 May 22 10:44 devkitPPC
-rw-r--r--  1 wii wii  834 May 21 10:27 dkarm-update.ini
-rw-r--r--  1 wii wii  319 May 21 10:27 dkppc-update.ini
drwxr-xr-x  7 wii wii 4096 May 21 10:27 examples
drwxr-xr-x  4 wii wii 4096 May 21 10:27 libgba
drwxr-xr-x  4 wii wii 4096 May 21 10:27 libmirko
drwxr-xr-x  4 wii wii 4096 May 21 10:27 libnds
drwxr-xr-x  4 wii wii 4096 May 21 10:27 libogc`
```

**Extracting your vWii NAND**