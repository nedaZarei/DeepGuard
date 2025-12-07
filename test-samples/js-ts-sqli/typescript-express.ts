// TypeScript Express routes with SQL injection vulnerabilities
// Demonstrates that type annotations don't prevent SQLi

import express, { Request, Response, NextFunction } from 'express';
import mysql from 'mysql2/promise';

const app = express();
app.use(express.json());

interface User {
  id: number;
  username: string;
  email: string;
  role: string;
}

interface Product {
  id: number;
  name: string;
  price: number;
  category: string;
}

const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'testdb'
});

// VULN: SQL Injection - typed parameters still vulnerable
app.get('/user/:id', async (req: Request, res: Response) => {
  const userId: string = req.params.id;
  // Line 34: Critical SQLi - type annotation doesn't prevent injection
  const query: string = `SELECT * FROM users WHERE id = ${userId}`;

  try {
    const [rows] = await pool.query<User[]>(query);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// VULN: SQL Injection - POST with typed request body
interface LoginRequest {
  username: string;
  password: string;
}

app.post('/login', async (req: Request<{}, {}, LoginRequest>, res: Response) => {
  const { username, password }: LoginRequest = req.body;
  // Line 52: Critical SQLi - typed interface doesn't prevent SQLi
  const query: string = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

  try {
    const [rows] = await pool.query<User[]>(query);
    if (rows.length > 0) {
      res.json({ success: true, user: rows[0] });
    } else {
      res.status(401).json({ success: false });
    }
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// VULN: SQL Injection - arrow function with types
const searchProducts = async (req: Request, res: Response): Promise<void> => {
  const searchTerm: string = req.query.q as string;
  const category: string = req.query.category as string;

  // Line 73: Critical SQLi - arrow function with types still vulnerable
  let sql: string = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`;

  if (category) {
    sql += ` AND category = '${category}'`;
  }

  try {
    const [rows] = await pool.query<Product[]>(sql);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
};

app.get('/search', searchProducts);

// VULN: SQL Injection - class method with types
class UserController {
  async updateUser(req: Request, res: Response): Promise<void> {
    const userId: number = parseInt(req.params.id);
    const email: string = req.body.email;

    // Line 96: High SQLi - class method with typed parameters
    const query: string = `UPDATE users SET email = '${email}' WHERE id = ${userId}`;

    try {
      await pool.query(query);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ error: (err as Error).message });
    }
  }
}

const userController = new UserController();
app.put('/user/:id', (req, res) => userController.updateUser(req, res));

app.listen(4000, (): void => {
  console.log('TypeScript Express server running on port 4000');
});

export default app;
