FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY ot_sec ot_sec
COPY data data
# Run as a non-root Linux user (basic hardening)
RUN useradd --create-home analyst && chown -R analyst /app
USER analyst
ENTRYPOINT ["python", "-m", "ot_sec"]
CMD ["--data", "data", "--out", "reports"]
