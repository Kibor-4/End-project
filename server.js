const express = require('express');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
const path = require('path');
const cors = require('cors');
const getPool = require('./database/db');
const userRoutes = require('./router/UserRoutes/signup');
const authRoutes = require('./router/AuthRoutes/auth'); // Renamed
const addPropertyRouter = require('./router/UserRoutes/addproperty');
const saleRouter = require('./router/UserRoutes/salerouter');
const profile = require('./router/UserRoutes/user');
const propertydetails = require('./router/UserRoutes/property');
const userdashboard = require('./router/UserRoutes/dash'); // Ensure this is correctly implemented
const home = require('./router/UserRoutes/index');
//const valuate = require('./router/UserRoutes/valuate');
const adminRoutes = require('./router/AdminRoutes/dashboard');
const propertyRoutes = require('./router/AdminRoutes/properties');
const analyticsRoutes = require('./router/AdminRoutes/analytics');
const settingsRoutes = require('./router/AdminRoutes/settings');
const transactionRoutes = require('./router/AdminRoutes/transaction');
const Users = require('./router/AdminRoutes/user_management');
//const user_dashboard = require('./router/UserRoutes/dash');

const fs = require('fs');

const app = express();

require('dotenv').config();

app.use((req, res, next) => {
    const now = new Date().toISOString();
    const logMessage = `${now} - ${req.method} ${req.url} - Session ID: ${req.sessionID || 'No Session'}\n`;

    fs.appendFile('server.log', logMessage, (err) => {
        if (err) {
            console.error('Error writing to log file:', err);
        }
    });

    console.log(logMessage.trim());
    next();
});

app.use(cors());

const sessionStore = new MySQLStore({
    host: process.env.DB_HOST,
    port: 3306,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    createDatabaseTable: true,
    schema: {
        tableName: 'user_sessions',
        columnNames: {
            session_id: 'session_id',
            expires: 'expires',
            data: 'data'
        }
    }
});

app.use(session({
    store: sessionStore,
    secret: process.env.SESSION_SECRET || 'your_secret_key', // Use env variable
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false, // Set to true in production with HTTPS
        maxAge: 1000 * 60 * 60 * 24,
        sameSite: 'lax'
    }
}));

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.set('view engine', 'ejs');

app.set('views', [
    path.join(__dirname, 'views/User'),
    path.join(__dirname, 'views/Admin'),
    path.join(__dirname, 'views/Shared'),
   
]);

app.use('/Public', express.static(path.join(__dirname, 'Public',)));

app.use('/', userRoutes);
app.use('/', authRoutes); // Use authRoutes
app.use('/', addPropertyRouter);
app.use('/', saleRouter);
app.use('/', profile);
app.use('/', propertydetails);
app.use('/', userdashboard); // Ensure this is correctly implemented
app.use('/', home);
//app.use('/', user_dashboard);
app.use('/', adminRoutes);
app.use('/', propertyRoutes);
app.use('/', analyticsRoutes);
app.use('/', settingsRoutes);
app.use('/', transactionRoutes);
app.use('/',Users);

app.get('/about', (req, res) => {
    res.render('about');
});
app.get('/',(req,res) =>{
    res.render('user_dashboard')
})

app.get('/logout', (req, res) => {
    console.log('Session before destruction:', req.session);
    req.session.destroy((err) => {
        if (err) {
            console.error('Error destroying session:', err);
            return res.status(500).send('Logout failed');
        }
        console.log('Session destroyed successfully');
        res.redirect('/login');
    });
});

app.use((err, req, res, next) => {
    console.error('Error stack:', err.stack);
    res.status(500).send('Something went wrong!');
});

async function startServer() {
    try {
        const pool = await getPool;
        console.log('Database connected successfully');

        const port = process.env.PORT || 8100;
        app.listen(port, () => {
            console.log(`Server running on port ${port}`);
        });
    } catch (err) {
        console.error("Failed to connect to database:", err);
        process.exit(1);
    }
}

startServer();