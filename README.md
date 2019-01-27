# STK500 client in Python

I needed to understand the STK500v1 protocol used by avrdude to flash Arduino
in order to reimplement it as a embedded one in C for the ESP32.

This is the end result. Works only for flashing a binary in the FLASH memory.
You can also dump the FLASH memory.

## Requirements

```
pip install pyserial progressbar2
```

## Usage

In the arduino, export your firmware as a binary (Sketch > Export as Compiled
Binary). Then:

```
python hex2bin.py PATH_TO_YOUR_FIRMWARE.hex firmware.bin
```

Then you can upload it:

```
python binuploader.py upload /dev/ttyUSB0 firmware.bin
```

You can also dump the memory:

```
python binuploader.py dump /dev/ttyUSB0
```
