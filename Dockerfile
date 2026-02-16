FROM node:20-slim

# whois-json shells out to the system whois binary
RUN apt-get update && apt-get install -y --no-install-recommends whois && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY . .

ENV PORT=3000
EXPOSE 3000

CMD ["node", "server.js"]
