const express = require("express");
const cors = require("cors");
const { poolcb } = require("./dbConfig");
const bcrypt = require("bcrypt");
const session = require("express-session");
const flash = require("express-flash");
const passport = require("passport");

const initializePassport = require("./passportConfig");
initializePassport(passport);

const app = express();

app.use(express.json()); // This method returns the middleware that only parses JSON and only looks at the requests where the content-type header matches the type option.
app.use(cors());

app.set("view engine", "ejs"); // view the ejs file

app.use(express.urlencoded({ extended: false }));

app.use(
    session({
        secret: "secret",
        resave: false,
        saveUninitialized: false
    })
);

app.use(passport.initialize());
app.use(passport.session());

app.use(flash());

app.get("/", (req, res) => {
    res.render("index");
});

app.get("/signin", checkAuthenticated, (req, res) => {
    res.render("signin");
})

app.get("/register", checkAuthenticated, (req, res) => {
    res.render("register");
})

app.get("/dashboard", checkNotAuthenticated, (req, res) => {
    res.render("dashboard", { user: req.user.name });
})

app.get('/logout', function (req, res, next) {
    req.logout(function (err) {
        if (err) { return next(err); }
        res.redirect('/');
    });
});

app.get('/exit', function(req,res){
    res.render("exit");
})

app.post('/register', async (req, res) => {
    let { name, email, password, password2 } = req.body;

    let errors = [];

    if (!name || !email || !password || !password2) {
        errors.push({ message: "Please enter all the fields" });
    }

    if (password.length < 6) {
        errors.push({ message: "Password should be atleast 6 characters" });
    }

    if (password != password2) {
        errors.push({ message: "Passwords do not match" });
    }

    if (errors.length > 0) {
        res.render('register', { errors });
    }
    else {
        let hashedPassword = await bcrypt.hash(password, 10);

        poolcb.query(
            `SELECT * FROM users WHERE email = $1`, [email], (err, results) => {
                if (err) {
                    throw err;
                }

                if (results.rows.length > 0) {
                    errors.push({ message: "Email already registered" });
                    res.render('signin', { errors });
                }
                else {
                    poolcb.query(
                        `INSERT INTO users(name, email, password)
                        VALUES ($1, $2, $3)
                        RETURNING id, email, password`, [name, email, hashedPassword], (err, results) => {
                        if (err) {
                            throw err;
                        }
                        console.log(results.rows);
                        req.flash("success_msg", "You are registered. Please login");
                        res.redirect("/signin");
                    }
                    )
                }
            }
        )
    }
});

app.post("/signin",
    passport.authenticate('local', {
        successRedirect: "/dashboard",
        failureRedirect: "/signin",
        badRequestMessage: 'Missing Credentials',
        failureFlash: true
    })
);

app.post('/dashboard', (req, res) => {

    let { fname, designation, project, division, accopen, accexp, username, diskquota, facility, email } = req.body;

    poolcb.query(
        `INSERT INTO records(fname, designation, project, division, accopen, accexp, username, diskquota, facility, email)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        RETURNING fname, designation, project, division, accopen, accexp, username, diskquota, facility, email`, [fname, designation, project, division, accopen, accexp, username, diskquota, facility, email], (err, results) => {
            if (err) {
                throw err;
            }
        console.log(results.rows);
        req.flash("success_msg", "Form Submitted");
        res.redirect("/exit");
    }
    )
});

function checkAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return res.redirect('/dashboard');
    }
    next();
}

function checkNotAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/signin');
}

app.listen(4000, () => {
    console.log(`Server on localhost 4000`);
})






// , designation, project, division, accopen, accexp, username, diskquota, facility, email


// SQL QUERIES USED TO CREATE THE TABLE

// select * from users;
// create table users (
// id bigserial primary key not null,
// name varchar(100) not null,
// email varchar(100) not null,
// password varchar(100) not null,
// unique (email)
// );

// select * from records;
// create table records (
// id bigserial primary key not null,
// fname varchar(100) not null,
// designation varchar(100) not null,
// project varchar(100) not null,
// division varchar(100) not null,
// accopen varchar(100) not null,
// accexp varchar(100) not null,
// username varchar(100) not null,
// diskquota int not null,
// facility varchar(100) not null,
// email varchar(100) not null
// );