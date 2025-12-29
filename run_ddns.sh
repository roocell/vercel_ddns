cd /home/roocell/vercel-ddns || exit 1

# run using venv python, load .env via python-dotenv in your script
./.venv/bin/python vercel_ddns.py --once >> ddns.log 2>&1

