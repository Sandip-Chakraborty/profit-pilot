# Profit Pilot Backend

## Files Structure
```
profit-pilot-backend/
├── server.js
├── package.json
├── .env.example
├── .gitignore
├── routes/
│   ├── auth.js
│   └── user.js
├── models/
│   └── User.js
└── middleware/
    └── auth.js
```

## Railway Deploy Steps
1. GitHub pe ye folder upload karo
2. Railway.app pe jaao
3. "New Project" → "Deploy from GitHub"
4. Environment variables add karo:
   - MONGO_URI
   - JWT_SECRET
5. Deploy ho jayega!
