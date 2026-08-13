FROM python:3.12-slim
RUN pip install --no-cache-dir flask==3.1.3 && useradd -m -u 10001 ctf
WORKDIR /app
COPY app/ /app/
RUN chown -R ctf:ctf /app
USER ctf
ENV PYTHONUNBUFFERED=1
EXPOSE 12081
CMD ["python3","app.py"]
