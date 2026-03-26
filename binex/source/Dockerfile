FROM ubuntu:26.04

RUN apt-get update && apt-get install -y \
    xinetd \
    gcc \
    make \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m -u 1001 challenge

WORKDIR /home/challenge
COPY Makefile chall.c flag.txt ./

RUN make && \
    chown root:root /home/challenge/flag.txt && \
    chmod 444 /home/challenge/flag.txt && \
    chmod 755 /home/challenge/chall && \
    chown challenge:challenge /home/challenge/chall

COPY challenge.xinetd /etc/xinetd.d/challenge
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 1337
CMD ["/entrypoint.sh"]