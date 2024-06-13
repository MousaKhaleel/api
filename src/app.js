const { MongoClient, ObjectId } = require('mongodb');
const express = require('express');
const morgan = require('morgan');
const helmet = require('helmet');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const middlewares = require('./middlewares');
const api = require('./api');

const app = express();

const client = new MongoClient(process.env.MOUSA_MONGODB_CONNECTION_STRING);
const myDb = client.db('Blog-Website');
const userCollection = myDb.collection('User-Accounts');
const blogCollection = myDb.collection('Blogs');

const secret = process.env.JWT_SECRET;

app.use(morgan('dev'));
app.use(helmet());
app.use(cors({ credentials: true, origin: true }));
app.use(express.json());
app.use(cookieParser());

app.get('/', (req, res) => {
    res.send('Server started');
});

app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const findAuthor = await userCollection.findOne({ 'Email': email, 'Password': password });
    if (findAuthor) {
        const token = jwt.sign({ name: findAuthor.Name, id: findAuthor._id, email }, secret, { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true }).json('ok');
    } else {
        res.status(400).json('Wrong info, try again');
    }
});

app.post('/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const existingUser = await userCollection.findOne({ 'Email': email });
        if (!existingUser) {
            await userCollection.insertOne({ 'Name': name, 'Email': email, 'Password': password, 'History': [] });
            res.send('Registration successful');
        } else {
            res.status(400).send('User already exists');
        }
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/profile', (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.status(401).json({ message: 'Unauthorized' });
    }

    jwt.verify(token, secret, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Unauthorized' });
        }

        res.json(decoded);
    });
});

app.post('/logout', (req, res) => {
    res.clearCookie('token').json('ok');
});

app.post('/addblog', async (req, res) => {
    try {
        const { title, preview, content, userId, tags } = req.body;
        await blogCollection.insertOne({ 'Title': title, 'Content': content, 'Preview': preview, 'AuthorID': userId, 'Tags': tags });
        res.send('Added successfully');
    } catch (error) {
        console.error('Error:', error);
        res.status(500).send('Internal Server Error');
    }
});

app.get('/allblogs', async (req, res) => {
    const page = parseInt(req.query.page);
    const limit = parseInt(req.query.limit);
    const skipBlogs = (page - 1) * limit;
    const allBlogs = await blogCollection.find({}).skip(skipBlogs).limit(limit).toArray();
    res.send(allBlogs);
});

app.get('/content/:id', async (req, res) => {
    const id = new ObjectId(req.params.id);
    const content = await blogCollection.findOne({ '_id': id });
    res.json(content);
});

app.get('/content/:id/:userId', async (req, res) => {
    const id = new ObjectId(req.params.id);
    const content = await blogCollection.findOne({ '_id': id });
    if (content) {
        await userCollection.updateOne({ '_id': new ObjectId(req.params.userId) }, { $pull: { History: id } });
        await userCollection.updateOne({ '_id': new ObjectId(req.params.userId) }, { $push: { History: id } });
    }
    res.json(content);
});

app.get('/history/:userId', async (req, res) => {
    const history = await userCollection.findOne({ '_id': new ObjectId(req.params.userId) });
    res.json(history.History);
});

app.get('/userblogs/:id', async (req, res) => {
    const id = req.params.id;
    const userBlogs = await blogCollection.find({ 'AuthorID': id }).toArray();
    res.json(userBlogs);
});

app.get('/historyblogs/:id', async (req, res) => {
    const id = new ObjectId(req.params.id);
    const historyBlogs = await blogCollection.findOne({ '_id': id });
    res.json(historyBlogs);
});

app.post('/recommendedblogs', async (req, res) => {
    try {
        const { topTags } = req.body;
        let result = await blogCollection.find({ Tags: { $all: topTags } }).toArray();

        if (result.length === 0) {
            result = await blogCollection.find({ Tags: { $in: topTags } }).toArray();
        }

        res.json(result);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.delete('/deletehistory/:userId', async (req, res) => {
    await userCollection.updateOne({ '_id': new ObjectId(req.params.userId) }, { $set: { History: [] } });
    res.json({ success: true });
});

app.post('/changePassword', async (req, res) => {
    const { userId, password } = req.body;
    await userCollection.updateOne({ '_id': new ObjectId(userId) }, { $set: { Password: password } });
    res.send('Password changed successfully');
});

app.delete('/deleteBlog/:id', async (req, res) => {
    const id = new ObjectId(req.params.id);
    await blogCollection.deleteOne({ '_id': id });
    await userCollection.updateMany({}, { $pull: { History: id } });
    res.json({ success: true });
});

app.use('/api/v1', api);

app.use(middlewares.notFound);
app.use(middlewares.errorHandler);

module.exports = app;
