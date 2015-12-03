## HBC Pack ##
(25 Sept '13)
http://www.mediafire.com/download/7y5ja8d7da2vv0c/Trinux+first+release.zip
```
This contains the boot.dol and the ppcboot.elf that you can use to run Linux off of an SD card on Wii or Wii U.
```
**details** (see meta.xml as well)

  * ppcboot.elf here is the MINI kernel from the code from this googlecode page

  * you can replace it with any other ppcboot.elf and the boot.dol should run it as well

  * if you replace it with the mikep5 kernel it should still run but when run on Wii U it complains a lot during startup and presents some other errors

  * you can add arguments to the meta.xml file. debug=1 will show a lot more text on screen during startup and bootmii=0 will try to run the ppcboot.elf file WITHOUT using the bootmii IOS. Unfortunately, the included linux kernel will not work without that IOS but other ppcboot.elf files do work (including mikep5)

  * This is meant to be run from SD. If it is not, it will look for the ppcboot.elf file in SD:/bootmii/ppcboot.elf unless you specify another location in an argument but it MUST be on SD.

## BootMii IOS ##
https://gbadev.googlecode.com/git/nswitch/wad/IOS254-64-v65281.wad

  * Since the above included Linux kernel does not actually presently boot without the BootMii IOS installed and the HackMii installer doesn't install said IOS on a Wii U, we've included the IOS WAD here for convenience until we've completely overcome issues making it's use necessary or the event that a future HackMii release DOES include it.

## Miscellaneous Tools ##
**ancast image decrypter**
http://www.mediafire.com/download/w5h12brbcuyz2hj/ancast+decrypter.zip
This dumps the decrypted part of an ancast image you've renamed to 00000017.app into a dump.bin file and then resets the Wii U console. Run with the "Launch Bootmii" option from HBC.

**Dump Mii NAND (NAND dumper)**
http://www.mediafire.com/download/tu97z15x94auuzm/Dump+Mii+NAND+v1.2.zip
This will dump the Wii/vWii NAND into a nand.bin file in the same format used by BootMii.