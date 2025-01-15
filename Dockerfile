FROM grammatech/ddisasm

ENV DEBIAN_FRONTEND=noninteractive 

# Max python version PeAR supports is python3.10, as gtirb python libs don't
# work with higher versions.

# Using python3.9 for better typing support than default Ubuntu 20 python (3.8)
# and easy installation
RUN apt-get update && apt-get install -y python3.9 python3-pip

COPY requirements.txt .
RUN python3.9 -m pip install -r requirements.txt

# Example invocation:
# docker run --platform linux/amd64 --rm -v $(pwd)/pear:/pear -v $(pwd):/w -it pear python3.9 -m pear --ir-cache /w/ir_cache --input-binary /w/in/switch_test/byte_switch --output-dir /w/out --gen-binary --gen-build-script --ignore-nonempty Identity
