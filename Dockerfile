FROM apify/actor-python:3.14

# Download kube-linter for amd64 (Apify cloud builder is always x86_64)
# v0.8.3: amd64 asset is 'kube-linter-linux' (no arch suffix); arm64 is 'kube-linter-linux_arm64'
ARG KUBE_LINTER_VERSION=0.8.3
RUN curl -fsSL -o /usr/local/bin/kube-linter       https://github.com/stackrox/kube-linter/releases/download/v${KUBE_LINTER_VERSION}/kube-linter-linux     && chmod +x /usr/local/bin/kube-linter

USER myuser

COPY --chown=myuser:myuser requirements.txt ./

RUN echo "Python version:"   && python --version   && echo "Pip version:"   && pip --version   && echo "Installing dependencies:"   && pip install -r requirements.txt   && echo "All installed Python packages:"   && pip freeze

COPY --chown=myuser:myuser . ./

RUN python -m compileall -q k8s_manifest_audit/

CMD ["python", "-m", "k8s_manifest_audit"]
