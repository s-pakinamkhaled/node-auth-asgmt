const express = require('express');
const { hashPassword, verifyPassword } = require('./password-utils');
const { signJWT, verifyJWT } = require('./jwt-utils');

const app = express();
app.use(express.json());

const PORT = 3000;
const JWT_SECRET = 'my_secret';

const books = [
  { id: 1, title: 'The Yacoubian Building', author: 'Alaa Al Aswany' },
  { id: 2, title: 'Palace Walk', author: 'Naguib Mahfouz' },
  { id: 3, title: 'Zaat', author: 'Sonallah Ibrahim' },
  { id: 4, title: 'The Map of Love', author: 'Ahdaf Soueif' },
  { id: 5, title: 'Woman at Point Zero', author: 'Nawal El Saadawi' },
];


const users = [];

function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];

  if (!token) return res.status(401).json({ message: 'Token required' });

  try {
    const payload = verifyJWT(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    res.status(403).json({ message: 'Invalid token', error: err.message });
  }
}

function authorizeAdmin(req, res, next) {
  if (req.user?.role !== 'admin')
    return res.status(403).json({ message: 'Admin role required' });

  next();
}

app.post('/register', (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password || !role)
    return res.status(400).json({ message: 'All fields required' });

  const existingUser = users.find((u) => u.username === username);
  if (existingUser)
    return res.status(409).json({ message: 'User already exists' });

  const hashedPassword = hashPassword(password); 
  users.push({ username, password: hashedPassword, role });

  res.status(201).json({ message: 'User registered' });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find((u) => u.username === username);

  if (!user) return res.status(401).json({ message: 'Invalid credentials' });

  const isValid = verifyPassword(password, user.password); 
  if (!isValid) return res.status(401).json({ message: 'Invalid credentials' });

  const token = signJWT({ username: user.username, role: user.role }, JWT_SECRET); 
  res.json({ token });
});

app.get('/books', (req, res) => {
  res.json(books);
});

app.get('/books/:id', (req, res) => {
  const book = books.find((b) => b.id === parseInt(req.params.id));
  if (!book) return res.status(404).json({ message: 'Book not found' });
  res.json(book);
});

app.post('/books', authenticate, authorizeAdmin, (req, res) => {
  const { title, author } = req.body;
  const newBook = { id: books.length + 1, title, author };
  books.push(newBook);
  res.status(201).json(newBook);
});

app.put('/books/:id', authenticate, authorizeAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const book = books.find((b) => b.id === id);

  if (!book) return res.status(404).json({ message: 'Book not found' });

  const { title, author } = req.body;
  book.title = title ?? book.title;
  book.author = author ?? book.author;
  res.json(book);
});

app.delete('/books/:id', authenticate, authorizeAdmin, (req, res) => {
  const id = parseInt(req.params.id);
  const index = books.findIndex((b) => b.id === id);
  if (index === -1) return res.status(404).json({ message: 'Book not found' });

  const deleted = books.splice(index, 1);
  res.json(deleted[0]);
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
