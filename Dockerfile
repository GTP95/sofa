FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get -y upgrade && apt-get install -y make cmake git gcc build-essential xz-utils && rm -rf /var/lib/apt/lists/* #keep image small

#Copy requirements file and install them first, so that this step can be cached
COPY requirements.txt .
#RUN pip install https://github.com/qilingframework/qiling/archive/dev.zip # Install Qiling from dev branch, currently the version on PyPI is more than 2 years old and doesn't support a thing needed for this project
RUN pip install --no-cache-dir -r requirements.txt

# Copy the project files
COPY . .

# Install arm-none-eabi toolchain

# Download the ARM GNU Toolchain
ADD https://developer.arm.com/-/media/Files/downloads/gnu/14.3.rel1/binrel/arm-gnu-toolchain-14.3.rel1-x86_64-arm-none-eabi.tar.xz arm-gnu-toolchain.tar.xz
# Untar and add to path
RUN mkdir arm-gnu-toolchain && tar -xf arm-gnu-toolchain.tar.xz -C arm-gnu-toolchain  --strip-components=1 && rm arm-gnu-toolchain.tar.xz
ENV PATH="$PATH:/app/arm-gnu-toolchain/bin"

#Build default targets
RUN make TARGET=AES PLATFORM=CW308_STM32F4
RUN make TARGET=KECCAK PLATFORM=CW308_STM32F4


#Add Raspberry pi challenge's firmware
ADD https://github.com/raspberrypi/rp2350_hacking_challenge_2.git /app/rp2350_hacking_challenge_2
WORKDIR /app/rp2350_hacking_challenge_2
RUN mkdir build
WORKDIR /app/rp2350_hacking_challenge_2/build
ENV PICO_SDK_FETCH_FROM_GIT="on"
RUN cmake -DPICO_PLATFORM=rp2350 -DPICO_BOARD=pico2 .. && make
WORKDIR /app

# Patch Qiling
RUN python3 sofa/tools/apply_qiling_patch.py

ENTRYPOINT ["python3", "main.py"]

# Default command (can be overridden at runtime)
CMD ["--help"]
