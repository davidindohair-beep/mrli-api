# Mr Li Purchase API

Backend API untuk Dashboard Pembelian Rambut - Indo Hair Corp

## Setup

```bash
# Install dependencies
npm install

# Copy environment file
cp .env.example .env

# Edit .env with your credentials
nano .env

# Run server
npm start
```

## Environment Variables

```
PORT=3006
DB_HOST=localhost
DB_USER=your_user
DB_PASSWORD=your_password
DB_NAME=mr_li_db
OPENAI_API_KEY=your_key
```

## API Endpoints

### Auth
- `POST /api/auth/login` - Login
- `POST /api/auth/logout` - Logout
- `GET /api/auth/check` - Check session

### Invoices
- `GET /api/invoices` - List invoices
- `POST /api/invoices` - Create invoice
- `DELETE /api/invoices/:id` - Delete invoice

### AI
- `POST /api/ai/openai` - AI proxy

## Repository
- GitHub: https://github.com/davidindohair-beep/mrli-api

---
© 2026 Indo Hair Corp
