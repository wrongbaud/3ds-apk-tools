# apk-tools
----
Tools for unpacking and repacking APK files found on various 3DS roms

---
## Usage:

* See ```apk.py``` for class definitions and example usage
* ```apk-template.bt``` is an 010 template for apk files that I made to assist in reverse engineering the format 

----
## Building a RomFS

See the following forum post for a decent tutorial on how to extract and rebuild a RomFS:

* https://gbatemp.net/threads/tutorial-how-to-decrypt-extract-rebuild-3ds-roms.383055/

----
## Gundam: The 3D Battle - Project notes and such...

* We are currently able to exctract textures from apk files, modify them, and then use these modified files using HANS.

* Since this is a JP cart however, and HANS dosen't support all regions we must do the following to get it to work.

1. Modify textures and recompress them into apk files, build the new RomFS
    * See Building a RomFS for more details
2. Start 3DS in gateway mode (requires flash cart)
    * Once in gateway mode, select the Gundam ROM on the flash cart
3. Enter homebrew launcher (either through  homebrew cia or other input vector)
4. Run HANS and redirect the RomFS transactions to your modified RomFS

This is not very efficient for testing (and requires a flash cart) so we may be able to use the LayerFS plugin capability of the NTR-CFW. Unfortunately though for this particular ROM, the toolkit to build the LaterFS plugin could not find a few of the symbols needed to perform the proper hooking to redirect RomFS access. This is something that we can probably find though. The layerFS build tools are included in this repo as well.

This issue was explained to me through someone on GBATemp (See link below):

* https://gbatemp.net/threads/ntr-cfw-layeredfs-freezing-at-launch-screen-for-gundam-the-3d-battle.424793/

----
## LayeredFS

LayeredFS is a plugin for NTR CFW that allows users to swap out individual files on their romFS with ones placed on the SD card, this is really useful for testing mods and would be beneficial to our long term workflow. The only problem is that it does not find all of the proper symbols in our Gundam rom in order to provide the necessary hooks to the CFW. The next step for us (if we want to employ this method) is to find the necessarry symbols for the ROM and enter them manually. The codebase is relatively straightforward and should work on a Linux host (I have modified the build scripts to work with a Linux system as opposed to it's original design which was Windows...

---
## Helpful Links for future work:
* https://gbatemp.net/threads/how-to-create-and-use-a-layeredfs-plugin.389977/
* https://gbatemp.net/threads/release-ntr-cfw-3-2-with-experimental-real-time-save-feature.385142/
* https://github.com/44670/layeredFS/wiki/manual
* https://github.com/44670/BootNTR/releases
* https://gbatemp.net/threads/release-3ds-simple-cia-converter.384559/
