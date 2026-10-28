#!/usr/bin/env python3
"""Simulasi PLC pengendali genset markas (Modbus TCP).

Coil 0 = status genset: 1 = NYALA, 0 = MATI.
Nilai awal NYALA. Bila ada perintah tulis (fc5/fc15) yang mematikan coil 0,
PLC mencatatnya sebagai genset dimatikan — inilah dampak serangan IT->OT.

Catatan: ini simulator ringan (pymodbus) yang menggantikan PLC/OpenPLC fisik
agar lab muat di satu laptop. Perilaku Modbus-nya nyata di kabel sehingga
Suricata tetap mendeteksi perintah tulis seperti pada PLC sungguhan.
"""
import logging
import sys

from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusServerContext,
    ModbusSlaveContext,
)
from pymodbus.server import StartTcpServer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("genset-plc")


class CoilBlock(ModbusSequentialDataBlock):
    """Datablock coil yang mencatat perubahan status genset."""

    def setValues(self, address, values):
        super().setValues(address, values)
        # address Modbus fc5 untuk coil 0 masuk sebagai address 1 di pustaka.
        if address in (0, 1):
            on = bool(values[0])
            if on:
                log.info("PERINTAH TULIS coil0=1  -> GENSET NYALA")
            else:
                log.warning("PERINTAH TULIS coil0=0  -> GENSET DIMATIKAN (dampak serangan)")


def build_context():
    coils = CoilBlock(0, [1] * 16)        # coil0 = genset NYALA
    di = ModbusSequentialDataBlock(0, [0] * 16)
    hr = ModbusSequentialDataBlock(0, [0] * 16)
    ir = ModbusSequentialDataBlock(0, [0] * 16)
    slave = ModbusSlaveContext(co=coils, di=di, hr=hr, ir=ir, zero_mode=True)
    return ModbusServerContext(slaves=slave, single=True)


if __name__ == "__main__":
    log.info("PLC genset-01 start; coil0=1 (NYALA); dengarkan Modbus TCP :502")
    StartTcpServer(context=build_context(), address=("0.0.0.0", 502))
