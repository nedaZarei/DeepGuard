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

/**
 * Retrieves user data from the database based on the user ID provided in the request parameters.
 *
 * @param {Request} req - The request object from the client containing the user ID in the parameters.
 * @param {Response} res - The response object used to send back user data or an error message.
 * @returns {Promise<void>} A promise that resolves to void after sending the JSON response.
 */
app.get('/user/:id', async (req: Request, res: Response) => {
  const userId: string = req.params.id;
  const query: string = `SELECT * FROM users WHERE id = ${userId}`;

  try {
    const [rows] = await pool.query<User[]>(query);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

interface LoginRequest {
  username: string;
  password: string;
}

/**
 * Handles user login by validating provided credentials.
 *
 * @param {Request<{}, {}, LoginRequest>} req - The HTTP request object containing login details.
 * @param {Response} res - The HTTP response object used to send back the desired HTTP response.
 * @returns {Promise<void>} A promise that resolves when the response has been sent.
 */
app.post('/login', async (req: Request<{}, {}, LoginRequest>, res: Response) => {
  const { username, password }: LoginRequest = req.body;
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

/**
 * Searches for products in the database based on a search term and optional category.
 *
 * @param {Request} req - The request object containing query parameters.
 * @param {Response} res - The response object used to send the results.
 * @returns {Promise<void>} A promise that resolves when the response has been sent.
 * @throws {Error} If there is an issue querying the database.
 */
const searchProducts = async (req: Request, res: Response): Promise<void> => {
  const searchTerm: string = req.query.q as string;
  const category: string = req.query.category as string;

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

class UserController {
/**
 * Updates the email of a user in the database.
 *
 * @param {Request} req - The request object containing the user's ID and new email.
 * @param {Response} res - The response object to send the result back to the client.
 * @returns {Promise<void>} A promise that resolves when the update is complete.
 * @throws {Error} If the database update fails.
 */
  async updateUser(req: Request, res: Response): Promise<void> {
    const userId: number = parseInt(req.params.id);
    const email: string = req.body.email;

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
/**
 * This function updates a user in the database.
 *
 * @param {Request} req - The HTTP request object containing user data.
 * @param {Response} res - The HTTP response object used to send a response.
 *
 * @returns {void} - Returns nothing.
 */
app.put('/user/:id', (req, res) => userController.updateUser(req, res));

/**
 * Logs a message indicating that the TypeScript Express server is running.
 *
 * @returns {void} This function does not return a value.
 */
app.listen(4000, (): void => {
  console.log('TypeScript Express server running on port 4000');
});

export default app;
