FROM python:3.14-trixie

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run the Python script directly to start the threaded servers
CMD ["python", "app.py"]
