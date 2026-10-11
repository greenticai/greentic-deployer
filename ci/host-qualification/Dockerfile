ARG BASE
FROM ${BASE}
RUN apt-get update && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/*
COPY simulator.py /opt/simulator.py
ENTRYPOINT ["python3", "/opt/simulator.py"]
