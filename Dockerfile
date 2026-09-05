FROM python:3.11-slim

WORKDIR /app

# સિસ્ટમ લાઈબ્રેરીઓ
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# પાઈથન ડિપેન્ડન્સીસ
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN python -m spacy download en_core_web_sm

# એપ્લિકેશન કોડ
COPY . .

EXPOSE 8080

CMD ["uvicorn", "gateway:app", "--host", "0.0.0.0", "--port", "8080"]