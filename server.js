const express = require('express');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key_change_in_production';
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/classroom_db';

// Database Models
const User = mongoose.model('User', new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['teacher', 'student'], default: 'student' },
  section: { type: String, default: 'General' }
}));

const Post = mongoose.model('Post', new mongoose.Schema({
  section: { type: String, required: true },
  title: { type: String, required: true },
  type: { type: String, enum: ['announcement', 'quiz', 'assignment'], default: 'announcement' },
  content: String,
  googleFormUrl: String,
  googleDocUrl: String,
  createdAt: { type: Date, default: Date.now }
}));

const Grade = mongoose.model('Grade', new mongoose.Schema({
  student: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  assessmentName: { type: String, required: true },
  score: { type: Number, required: true },
  maxScore: { type: Number, default: 100 }
}));

// Middlewares
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access Denied: No Token Provided' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or Expired Token' });
    req.user = user;
    next();
  });
};

const requireTeacher = (req, res, next) => {
  if (req.user.role !== 'teacher') {
    return res.status(403).json({ error: 'Access Denied: Teacher Privileges Required' });
  }
  next();
};

// Auth Routes
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, role, section } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await User.create({ name, email, password: hashedPassword, role, section });
    res.status(201).json({ message: 'User created successfully', userId: user._id });
  } catch (err) {
    res.status(400).json({ error: 'User registration failed. Email might already exist.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user._id, role: user.role, name: user.name, section: user.section }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token, role: user.role, name: user.name, section: user.section });
});

// Teacher Admin Endpoints
app.post('/api/teacher/posts', authenticateToken, requireTeacher, async (req, res) => {
  try {
    const { section, title, type, content, googleFormUrl, googleDocUrl } = req.body;
    const post = await Post.create({ section, title, type, content, googleFormUrl, googleDocUrl });
    res.status(201).json(post);
  } catch (err) {
    res.status(500).json({ error: 'Failed to create post' });
  }
});

app.post('/api/teacher/randomize-groups', authenticateToken, requireTeacher, async (req, res) => {
  const { section, mode, count } = req.body;
  const students = await User.find({ section, role: 'student' });
  if (students.length === 0) return res.status(400).json({ error: 'No students found in this section' });

  let shuffled = [...students].sort(() => 0.5 - Math.random());
  let groups = [];

  if (mode === 'numGroups') {
    const numGroups = parseInt(count);
    for (let i = 0; i < numGroups; i++) groups.push([]);
    shuffled.forEach((student, index) => {
      groups[index % numGroups].push(student.name);
    });
  } else {
    const perGroup = parseInt(count);
    while (shuffled.length > 0) {
      groups.push(shuffled.splice(0, perGroup).map(s => s.name));
    }
  }
  res.json({ groups });
});

app.post('/api/teacher/grades', authenticateToken, requireTeacher, async (req, res) => {
  try {
    const { studentId, assessmentName, score, maxScore } = req.body;
    const grade = await Grade.create({ student: studentId, assessmentName, score, maxScore });
    res.status(201).json(grade);
  } catch (err) {
    res.status(500).json({ error: 'Failed to record grade' });
  }
});

app.get('/api/teacher/students', authenticateToken, requireTeacher, async (req, res) => {
  const students = await User.find({ role: 'student' }).select('-password');
  res.json(students);
});

// Student & Stream Endpoints
app.get('/api/posts/:section', authenticateToken, async (req, res) => {
  const posts = await Post.find({ section: req.params.section }).sort({ createdAt: -1 });
  res.json(posts);
});

app.get('/api/student/my-grades', authenticateToken, async (req, res) => {
  const grades = await Grade.find({ student: req.user.id });
  res.json(grades);
});

// Start Server
mongoose.connect(MONGODB_URI)
  .then(() => {
    app.listen(3000, () => console.log('Server running on http://localhost:3000'));
  })
  .catch(err => console.error('MongoDB connection error:', err));
