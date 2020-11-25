FROM ubuntu:16.04
RUN apt-get update -y && \
    apt-get install -y python-pip python-dev && \
    apt-get install -y git && \
    apt-get install -y python-crypto && \
    apt-get install -y swig && \
    apt-get install -y build-essential && \
    apt-get install -y libusb-dev pcscd pcsc-tools libpcsclite-dev libccid

RUN git clone https://github.com/MichaelTwito/shadysim_mod

RUN git clone https://github.com/MichaelTwito/pySim_mod.git

RUN pip install pyscard  && \
    pip install pyyaml
   
#WORKDIR /shadysim_mod
CMD service pcscd start && \
    python /shadysim_mod/shadysim_mod.py --pcsc -l /shadysim_mod/applet.cap -i /shadysim_mod/applet.cap --kic $KIC --kid $KID --module-aid A00000015141434C00 --instance-aid A00000015141434C00 && \
    python /shadysim_mod/shadysim.py --pcsc --kic $KIC --kid $KID --aram-apdu 80E2900033F031E22FE11E4F06FFFFFFFFFFFFC114E46872F28B350B7E1F140DE535C2A8D5804F0BE3E30DD00101DB080000000000000001 && \
    python /shadysim_mod/shadysim.py --pcsc --kic $KIC --kid $KID --aram-apdu 80CAFF4000

