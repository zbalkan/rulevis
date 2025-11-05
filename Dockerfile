FROM python:3.12-slim

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 5000

VOLUME ["/rules/builtin", "/rules/custom"]

ENTRYPOINT ["/bin/sh", "-c", "python src/rulevis.py -p \"${RULE_PATH:-/rules/builtin,/rules/custom}\""]
