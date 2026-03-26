FROM ubuntu:26.04

RUN apt-get update && apt-get install -y \
    xinetd \
    gcc \
    make \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1001 challenge

RUN mkdir -p /home/challenge/dev /home/challenge/bin /home/challenge/lib /home/challenge/lib64 /home/challenge/usr/lib

RUN cp -R /lib/x86_64-linux-gnu /home/challenge/lib/ && \
    cp -R /lib64/* /home/challenge/lib64/ || true && \
    cp -R /usr/lib/x86_64-linux-gnu /home/challenge/usr/lib/

RUN mknod /home/challenge/dev/null c 1 3 && \
    mknod /home/challenge/dev/zero c 1 5 && \
    mknod /home/challenge/dev/random c 1 8 && \
    mknod /home/challenge/dev/urandom c 1 9 && \
    chmod 666 /home/challenge/dev/*

WORKDIR /root

COPY Makefile chall.c ./

RUN make && mv chall /home/challenge/chall

COPY flag.txt /home/challenge/
RUN chown -R root:root /home/challenge && \
    chmod -R 755 /home/challenge && \
    chmod 444 /home/challenge/flag.txt

COPY challenge.xinetd /etc/xinetd.d/challenge
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

WORKDIR /home/challenge
EXPOSE 1337
CMD ["/entrypoint.sh"]