FROM grammatech/ddisasm

ENV DEBIAN_FRONTEND=noninteractive 

# using python3.9 for better typing, default is python 3.8 on ubuntu 20
# python3.10 is also available but requires 300MB download and 1.5GB disk space
# (vs python3.9 which needs 5k download and 24MB disk space)
# Also, gtirb-rewriting works with 3.9. Haven't tested if it works with 3.10
RUN apt-get update && apt-get install -y python3.9 python3-pip

# ssh neededsshssh   for gtirb-pprinter remote build server
RUN apt update --fix-missing
RUN apt-get install -y ssh

COPY add_nop/requirements.txt .
RUN python3.9 -m pip install -r requirements.txt

# module should be provided through volume mount
#ENTRYPOINT ["/bin/bash"]
ENTRYPOINT ["python3.9",  "-m", "add_nop"]
