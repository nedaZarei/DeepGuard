// Authentication module with vulnerabilities
import { Request, Response } from 'express';
import * as crypto from 'crypto';

interface User {
  id: number;
  username: string;
  passwordHash: string;
}

// Weak cryptographic hash - MD5
export function hashPassword(password: string): string {
  // VULNERABLE: Using MD5 for password hashing
  return crypto.createHash('md5').update(password).digest('hex');
}

// SQL Injection in login
export async function login(req: Request, res: Response, db: any) {
  const { username, password } = req.body;
  const passwordHash = hashPassword(password);

  // VULNERABLE: String concatenation in SQL query
  const query = `SELECT * FROM users WHERE username = '${username}' AND password_hash = '${passwordHash}'`;

  db.query(query, (err: Error, results: User[]) => {
    if (err) {
      res.status(500).json({ error: 'Internal server error' });
      return;
    }

    if (results.length > 0) {
      res.json({ success: true, user: results[0] });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
}

// Hardcoded secret
export const JWT_SECRET = 'super-secret-key-12345';

export function generateToken(userId: number): string {
  // Using hardcoded secret
  const payload = { userId, iat: Date.now() };
  return crypto.createHmac('sha256', JWT_SECRET)
    .update(JSON.stringify(payload))
    .digest('hex');
}
