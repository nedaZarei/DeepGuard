// Sample vulnerable Express.js TypeScript code with SQL injection vulnerabilities

import express, { Request, Response } from 'express';
import mysql from 'mysql';

const app = express();
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'testdb'
});

interface User {
  id: number;
  username: string;
  email: string;
}

// VULNERABLE: SQL injection via query parameter
app.get('/user', (req: Request, res: Response) => {
  const userId: string = req.query.id as string;
  const query = `SELECT * FROM users WHERE id = ${userId}`; // SQLi vulnerability

  db.query(query, (err, results: User[]) => {
    if (err) throw err;
    res.json(results);
  });
});

// VULNERABLE: SQL injection in arrow function
const getProductById = (req: Request, res: Response): void => {
  const productId = req.params.id;
  const sql = 'SELECT * FROM products WHERE id = ' + productId; // SQLi vulnerability

  db.query(sql, (error, rows) => {
    if (error) throw error;
    res.send(rows);
  });
};

app.get('/product/:id', getProductById);

// VULNERABLE: SQL injection in async method
class UserController {
  async login(req: Request, res: Response): Promise<void> {
    const { username, password } = req.body;
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`; // SQLi vulnerability

    db.query(query, (err, results) => {
      if (err) throw err;
      res.json({ success: results.length > 0 });
    });
  }
}

const userController = new UserController();
app.post('/login', (req, res) => userController.login(req, res));

app.listen(3000);
