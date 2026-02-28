# PhishShield AI — Deployment Guide

## Prerequisites
- Python 3.10+
- pip

## Quick Start (Local)

```bash
git clone <repo-url>
cd phishshield-ai
python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open http://localhost:5000

Default admin credentials are printed to the console on first run. **Save them immediately — they are randomly generated.**

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | random | Flask secret key (set a strong value in prod) |
| `DATABASE_URL` | `sqlite:///phishshield.db` | Database connection string |
| `MAIL_SERVER` | `smtp.gmail.com` | SMTP server |
| `MAIL_USERNAME` | — | Email username |
| `MAIL_PASSWORD` | — | Email password |

Create a `.env` file (never commit this):
```
SECRET_KEY=your-very-long-random-secret-here
DATABASE_URL=sqlite:///phishshield.db
```

---

## Production Deployment (Gunicorn + Nginx)

### 1. Install Gunicorn
```bash
pip install gunicorn
```

### 2. Run with Gunicorn
```bash
gunicorn -w 4 -b 0.0.0.0:8000 "app:app"
```

### 3. Nginx config snippet
```nginx
server {
    listen 80;
    server_name yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /static/ {
        alias /path/to/phishshield/static/;
    }
}
```

### 4. Enable HTTPS cookies
Set `SESSION_COOKIE_SECURE = True` in `config.py` when running with HTTPS.

---

## Docker (optional)

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
EXPOSE 8000
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:8000", "app:app"]
```

```bash
docker build -t phishshield .
docker run -p 8000:8000 -e SECRET_KEY=yourkey phishshield
```

---

## Database Initialization
The database is auto-created on first run via `db.create_all()` in `app.py`. For production, use Flask-Migrate for schema migrations.

## Security Checklist
- [ ] Change the default admin password immediately
- [ ] Set `SESSION_COOKIE_SECURE = True` (requires HTTPS)
- [ ] Use a strong, random `SECRET_KEY`
- [ ] Enable HTTPS with Let's Encrypt
- [ ] Set up rate limiting (Flask-Limiter)
- [ ] Review and harden CORS settings
