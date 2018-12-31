FROM python:alpine
LABEL maintainer="mwgrunny@gmail.com"
ARG VERSION=0.10.0
RUN pip install zapcli==$VERSION

ENTRYPOINT [ "zap-cli" ]
