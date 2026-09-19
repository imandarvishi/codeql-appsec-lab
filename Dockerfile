FROM python:3.12.11-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt ./
RUN python -m pip install --no-cache-dir -r requirements.txt
RUN addgroup --system app && adduser --system --ingroup app --uid 10001 app
COPY --chown=app:app app.py ./
USER 10001:10001
EXPOSE 5000
CMD ["python", "app.py"]
