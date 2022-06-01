FROM perl:5.10-buster

RUN apt update -y
RUN apt upgrade -y
RUN apt install cpanminus wget libssl-dev flex bison curl less -y
RUN apt clean -y

RUN mkdir /app
WORKDIR /app

COPY . /app

RUN cpanm Bundle::LWP
RUN cpanm Net::DNS
RUN cpanm Net::FTP
RUN cpanm TFTP
RUN cpanm Time::HiRes
RUN cpanm Socket
RUN cpanm IO::Socket
RUN cpanm Getopt::Std
RUN cpanm IO::Socket::SSL