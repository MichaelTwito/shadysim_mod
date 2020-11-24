FROM ubuntu:16.04
RUN apt-get update -y && \
    apt-get install -y python-pip python-dev &&\
    apt-get install -y git

RUN git clone https://github.com/MichaelTwito/shadysim_mod

WORKDIR /shadysim_mod

CMD python shadysim_mod.py --help


