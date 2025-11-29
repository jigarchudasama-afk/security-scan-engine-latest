FROM registry.access.redhat.com/ubi8/ubi:latest

LABEL maintainer="jigar.chudasama@motorolasolutions.com"
LABEL description="Containerized STIG and OpenSCAP scanner which scans host machine"

RUN dnf install -y tar gzip bzip2 wget openscap-scanner python3 && dnf clean all

RUN mkdir -p /app /scanner_files

WORKDIR /app

COPY Vulnerability/ /scanner_files/

COPY run_STIG.sh .
COPY run_openScap.sh .
COPY security_scans_wrapper.sh .
COPY email.sh .

RUN chmod +x run_STIG.sh run_openScap.sh security_scans_wrapper.sh email.sh

CMD ["/app/security_scans_wrapper.sh"]