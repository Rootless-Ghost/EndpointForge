FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Inside the container the app must listen on all interfaces so the port
# mapping works. Publish it to the host's loopback only:
#   docker run -p 127.0.0.1:5005:5005 endpointforge
# The login URL (with access token) is printed to `docker logs`.
ENV ENDPOINTFORGE_HOST=0.0.0.0
ENV PYTHONUNBUFFERED=1

EXPOSE 5005

CMD ["python", "app.py"]
