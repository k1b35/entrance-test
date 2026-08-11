# PoC не имеет зависимостей вне стандартной библиотеки, поэтому образ тривиален.
# Это осознанное решение: в целевой системе здесь был бы образ с ONNX Runtime и
# CUDA, но тащить его в PoC значило бы менять предмет проверки (см. WORKLOG.md).
FROM python:3.12-slim

WORKDIR /app
COPY . /app

ENV PYTHONUNBUFFERED=1 PYTHONIOENCODING=utf-8

# Тесты прогоняются при сборке: образ, где инварианты безопасности не выполняются,
# собираться не должен.
RUN python -m unittest discover -s tests -q

CMD ["python", "scripts/run_demo.py"]
