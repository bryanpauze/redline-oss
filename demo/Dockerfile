# Redline demo recorder: runs the scripted scan in a container and renders a GIF + MP4.
# Self-contained; no external services. Build from the repo root:
#   docker build -f demo/Dockerfile -t redline-demo .
#   docker run --rm -v "$PWD/demo/out:/out" redline-demo
FROM python:3.12-slim

ARG TARGETARCH=arm64
RUN apt-get update && apt-get install -y --no-install-recommends \
      curl ca-certificates ffmpeg && rm -rf /var/lib/apt/lists/*

# asciinema records the terminal session; agg renders the cast to a GIF (no browser needed)
RUN pip install --no-cache-dir asciinema
RUN case "$TARGETARCH" in \
      arm64) A=aarch64-unknown-linux-gnu ;; \
      amd64) A=x86_64-unknown-linux-musl ;; \
      *) A=x86_64-unknown-linux-musl ;; esac; \
    curl -fsSL -o /usr/local/bin/agg \
      "https://github.com/asciinema/agg/releases/download/v1.9.0/agg-${A}" \
    && chmod +x /usr/local/bin/agg

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY redline ./redline
COPY tests ./tests
RUN pip install --no-cache-dir .

COPY demo/demo.sh /app/demo.sh
RUN chmod +x /app/demo.sh

# record demo.sh -> cast -> gif, then gif -> mp4 (both land in the mounted /out)
RUN printf '#!/usr/bin/env bash\nset -e\n\
asciinema rec --overwrite --cols 100 --rows 32 --command "bash /app/demo.sh" /tmp/redline.cast\n\
agg --font-size 15 --theme asciinema --speed 1.4 /tmp/redline.cast /out/redline.gif\n\
ffmpeg -y -i /out/redline.gif -movflags +faststart -pix_fmt yuv420p \
  -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" /out/redline.mp4 2>/dev/null\n\
echo "wrote /out/redline.gif and /out/redline.mp4"\n' > /usr/local/bin/record && chmod +x /usr/local/bin/record

ENV TERM=xterm-256color
ENTRYPOINT ["record"]
