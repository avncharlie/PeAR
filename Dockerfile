FROM grammatech/ddisasm

ENV DEBIAN_FRONTEND=noninteractive 

# Max python version PeAR supports is python3.10, as gtirb python libs don't
# work with higher versions.

# Using python3.9 for better typing support than default Ubuntu 20 python (3.8)
# and easy installation
RUN apt-get update && apt-get install -y python3.9 python3-pip

# ssh needed for gtirb-pprinter remote build server
RUN apt update --fix-missing
RUN apt-get install -y ssh

COPY pear/requirements.txt .
RUN python3.9 -m pip install -r requirements.txt

# module should be provided through volume mount
#ENTRYPOINT ["/bin/bash"]
ENTRYPOINT ["python3.9",  "-m", "pear"]
