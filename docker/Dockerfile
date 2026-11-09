# Target application for GHSA-xqc2-xf4c-x3h3.
#
# One image serves both tiers; compose picks the entrypoint. REACT_VERSION
# selects the package set, so the identical application runs vulnerable (19.2.8)
# or patched (19.2.9) with nothing else changed.
FROM node:22-alpine

ARG REACT_VERSION=19.2.8
ENV REACT_VERSION=${REACT_VERSION}
ENV NODE_ENV=production

WORKDIR /srv

# `webpack` is only a peer for the bundler plugin, which this app does not use.
RUN npm init -y >/dev/null \
 && npm install --no-audit --no-fund --legacy-peer-deps \
      react@${REACT_VERSION} \
      react-dom@${REACT_VERSION} \
      react-server-dom-webpack@${REACT_VERSION} \
 && npm ls --depth=0 2>/dev/null || true

COPY app/ /srv/app/

# Where the PoC payload leaves its evidence. Compose bind-mounts a host
# directory here so the exploit can read the result back without any extra
# endpoint on the application.
RUN mkdir -p /proof

EXPOSE 3000 3001

HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=10 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# Overridden per service in compose.yaml.
CMD ["node", "app/web-server.mjs"]
