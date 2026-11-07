# Simulator PLC genset (Modbus TCP) berbasis pymodbus. Ringan & arm64-native.
FROM python:3.12-slim
RUN pip install --no-cache-dir "pymodbus==3.6.9"
COPY genset_plc.py hmi.py /app/
WORKDIR /app
EXPOSE 502
CMD ["python3", "genset_plc.py"]
