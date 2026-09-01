FROM mcr.microsoft.com/playwright/python:v1.62.0-noble

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY defacement_check.py .

RUN mkdir -p \
    /app/website_data/baselines \
    /app/website_data/baseline_screenshots \
    /app/website_data/screenshots \
    /app/website_data/comparisons \
    /app/website_data/evidence

CMD ["python3", "defacement_check.py"]
