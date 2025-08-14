FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get -y upgrade && apt-get install -y make gcc build-essential xz-utils && rm -rf /var/lib/apt/lists/* #keep image small

#Copy requirements file and install them first, so that this step can be cached
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the project files
COPY . .

# Install arm-none-eabi toolchain

# Download the ARM GNU Toolchain
ADD https://developer.arm.com/-/media/Files/downloads/gnu/14.3.rel1/binrel/arm-gnu-toolchain-14.3.rel1-x86_64-arm-none-eabi.tar.xz arm-gnu-toolchain.tar.xz
# Untar to /usr/local/bin
RUN mkdir arm-gnu-toolchain && tar -xf arm-gnu-toolchain.tar.xz -C arm-gnu-toolchain  --strip-components=1 && rm arm-gnu-toolchain.tar.xz && mv arm-gnu-toolchain/bin/* /usr/local/bin/ && rm -rf arm-gnu-toolchain

#Build default targets
RUN make TARGET=AES PLATFORM=CW308_STM32F4
RUN make TARGET=KECCAK PLATFORM=CW308_STM32F4

# Patch Qiling
RUN python3 armchair/tools/apply_qiling_patch.py

ENTRYPOINT ["python3", "main.py"]

# Default command (can be overridden at runtime)
CMD ["--help"]
