FROM node:20-bookworm-slim
RUN useradd -m -u 10001 ctf
WORKDIR /app
COPY app/package.json /app/package.json
RUN npm install --omit=dev --no-audit --no-fund
COPY app/ /app/
COPY flag.txt /flag.txt
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && chown -R ctf:ctf /app
EXPOSE 12756
ENTRYPOINT ["/entrypoint.sh"]
