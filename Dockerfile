FROM python:3.7-slim

COPY ./requirements.txt /tmp/

RUN apt-get update \
    && apt-get install -y git \
                          curl \
                          gnupg2 \
                          software-properties-common

RUN pip --no-cache-dir install -U pip \
    && pip --disable-pip-version-check --no-cache-dir install -r /tmp/requirements.txt \
    && pip --disable-pip-version-check --no-cache-dir install pylint \
                                                              pylama \
                                                              flake8 \
                                                              isort \
                                                              pydocstyle \
                                                              autopep8 \
                                                              black \
                                                              responses \
                                                              pytest \
                                                              datadiff

RUN curl https://raw.githubusercontent.com/helm/helm/master/scripts/get-helm-3 | bash
RUN curl -fsSL https://apt.releases.hashicorp.com/gpg | apt-key add - \
    && apt-add-repository "deb [arch=amd64] https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
    && apt-get update \
    && apt-get install vault
