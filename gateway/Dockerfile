FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund
COPY server.mjs ./
# Files arrive with the Mac's private permissions (600); let the unprivileged node user read them.
RUN chmod -R a+rX /app
USER node
EXPOSE 8080
CMD ["node", "server.mjs"]
