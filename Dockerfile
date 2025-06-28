FROM python:3.11-slim

WORKDIR /app

# Copia tudo da raiz para o container
COPY . .

RUN pip install --no-cache-dir -r requirements.txt

CMD ["python", "main.py"]
# CMD ["python", "tests/test.py"]
