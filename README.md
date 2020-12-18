# libmodbus_ASF4
libmodbus compatible with Atmel Studio Framework 4 (aka Atmel Start)

Initialization of peripherals in ASF4 is done in a single file, which I am not providing here.

This library works at baudrate of 115200 on a 16MHz clock for both the cpu and the uart peripheral.
This do not work at 115200 at 4MHz, no matter what I try with critical section and interrupt masking.

At 115200 It is possible to make nearly 400 transactions per second, it will likely be necessary to pump up the baudrate.

This is licenced in LGPLv2.1 to conform with the [original libmodbus library](https://github.com/stephane/modbusino)