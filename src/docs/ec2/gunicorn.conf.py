import multiprocessing

bind = 'unix:/run/gunicorn.sock'
workers = multiprocessing.cpu_count() * 2 + 1
timeout = 30
