FROM jenkins-agent/stretch

RUN apt-get update && \
    apt-get install -y \
                # poetry depends on that the python executable exists...
				python3-dev \
				python3-pip \
    && rm -rf /var/lib/apt/lists/*
