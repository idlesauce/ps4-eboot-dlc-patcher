# ps4-5-eboot-dlc-patcher

## This project is very much in an experimental stage. Dont expect it to be reliable.


Patches the eboot to load a custom .prx  containing the dlc content ids, and all functions from `libSceAppContent`,
emulating some of the functions from it:
```
sceAppContentGetAddcontInfoList
sceAppContentGetAddcontInfo
sceAppContentGetEntitlementKey
sceAppContentAddcontDelete
sceAppContentAddcontMount
sceAppContentAddcontUnmount
sceAppContentGetPftFlag
```
The other functions are "proxied" to the real `libSceAppContent` library.
Some of the newer cross-gen games use the `libSceNpEntitlementAccess` library, this is currently not emulated, however i plan at least partially support it.

This is made for ps4 fpkgs, running on ps5, where dlc fpkgs dont work, although i guess it might also be useful for games where the main game is unlocked with dlcs so it can all be in one pkg (like some telltale games).



- Requires IDA Pro 7.5 with https://github.com/SocraticBliss/ps4_module_loader plugin installed and python version 3.9/3.10 (dont copy in the python folder)
- Useful for extracting and repacking pkgs: 
  - https://www.mediafire.com/file/xw0zn2e0rjaf5k7/Patch_Builder_v1.3.3.zip/file
  - https://www.psxhax.com/threads/ps4-patch-builder-for-building-modded-update-pkgs-by-modded-warfare.7112/
- selfutil
  - https://github.com/xSpecialFoodx/SelfUtil-Patched


## Usage:
1. Extract eboot.bin from update (or base pkg if you dont have an update) and un-fself it.
1. Load eboot.elf in IDA (Make sure you select `PS4 - Main Module - ASLR` type when opening, if you dont see this option the eboot.bin might be an fself still)
1. Wait for analysis to finish. The bar at the top should be mostly blue (Regular functions)
1. Go to File->Script file... and select the python script from this repo.
1. Follow the instructions, if you see `Patching complete` you're good.
1. Extract all files from the update pkg.
1. Replace the eboot.bin from the extracted update pkg's Image0 folder with our patched one (rename to eboot.bin), and place `dlcldr.prx` next to it.
1. During the patching process you were asked to input a list of content ids. For each of the content ids you entered in the box for `DLCs with extra data`, you'll need to create a new folder in Image0 named `dlcXX` where XX is the index from 0, in the same order you entered in the textbox. In this new folder youll need to copy the contents of the Image0 folder of the respective extracted dlc. See below for example:
    ```
    GEDLC00000000001 -> dlc00/
    TRAUMAPACK000000 -> dlc01/
    GEPREDLC00000001 -> dlc02/
    ```
1. Repack update pkg and you're done

## Notes:
- You can use Modded Warfare's Patch Builder to get the content id, itll look something like this:
  ```
  Content ID: UP0102-CUSA18017_00-GEDLC00000000001
  ```
  You need the last bit from it `GEDLC00000000001`

- Patch Builder also shows whether a dlc has extra data or not, or you can also see by checking if the dlc pkg has an Image0 folder or not.


Credits to [jocover](https://github.com/jocover) for discovering the functions responsible for loading dlcs.
