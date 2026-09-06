import multiprocessing

# Server Socket
bind = "0.0.0.0:8080"
backlog = 2048

# Worker Processes (CPU કોર આધારિત સ્કેલિંગ)
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "uvicorn.workers.UvicornWorker"
worker_connections = 1000
timeout = 60
keepalive = 5

# Logging & Telemetry
loglevel = "info"
accesslog = "-"
errorlog = "-"