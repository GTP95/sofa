FROM python:3.12-slim

# Install system dependencies
RUN apt-get update && apt-get -y upgrade && apt-get install -y make cmake git gcc build-essential xz-utils && rm -rf /var/lib/apt/lists/* #keep image small
#devcontainer assumes this user exists
RUN useradd -ms /bin/bash ubuntu

USER ubuntu
WORKDIR /home/ubuntu

# Install arm-none-eabi toolchain

# Download the ARM GNU Toolchain and set correct permissions
ADD https://developer.arm.com/-/media/Files/downloads/gnu/14.3.rel1/binrel/arm-gnu-toolchain-14.3.rel1-x86_64-arm-none-eabi.tar.xz /home/ubuntu/arm-gnu-toolchain.tar.xz
USER root
RUN chown ubuntu:ubuntu /home/ubuntu/arm-gnu-toolchain.tar.xz
USER ubuntu

# Untar and add to path
RUN mkdir arm-gnu-toolchain && tar -xf arm-gnu-toolchain.tar.xz -C arm-gnu-toolchain  --strip-components=1 && rm arm-gnu-toolchain.tar.xz
ENV PATH="$PATH:/home/ubuntu/arm-gnu-toolchain/bin"


#Add Raspberry pi challenge's firmware. All this fiddling with permissions just to not directly clone with git...
#I expected the ADD command to be smarter
ADD https://github.com/raspberrypi/rp2350_hacking_challenge_2.git /home/ubuntu/rp2350_hacking_challenge_2
USER root
RUN chown -R ubuntu:ubuntu /home/ubuntu/rp2350_hacking_challenge_2
USER ubuntu
WORKDIR /home/ubuntu/rp2350_hacking_challenge_2
RUN mkdir build
WORKDIR /home/ubuntu/rp2350_hacking_challenge_2/build
ENV PICO_SDK_FETCH_FROM_GIT="on"
RUN cmake -DPICO_PLATFORM=rp2350 -DPICO_BOARD=pico2 .. && make
WORKDIR /home/ubuntu

ENTRYPOINT ["sh"]
