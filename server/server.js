const dotenv = require("dotenv");
const express = require("express");
const cors = require("cors");
const pool = require("./database");
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

app.set("view engine", "ejs");
// view the ejs file

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
    // res.send("HELLO FROM SERVER");
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

app.get("/logout", (req, res) => {
    req.logOut();
    req.flash("success_msg", "YOU HAVE LOGOUT");
    res.redirect("/login");
}); 



app.post('/register', async (req, res) => {
    let { name, email, password, password2 } = req.body;

    console.log({
        name, email, password, password2
    });

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
        console.log(hashedPassword);

        poolcb.query(
            `SELECT * FROM users
            WHERE email = $1`,
            [email],
            (err, results) => {
                if (err) {
                    throw err;
                }
                console.log(results.rows);
                if (results.rows.length > 0) {
                    errors.push({ message: "Email already registered" });
                    res.render('register', { errors });
                }
                else {
                    pool.query(
                        `INSERT INTO users(name, email, password)
                        VALUES ($1, $2, $3)
                        RETURNING id, password`, [name, email, hashedPassword], (err, results) => {
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
        failureFlash: true
    })
);

function checkAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return res.redirect('/dashboard');
    }
    next();
}

function checkNotAuthenticated(req, res, next){
    if(req.isAuthenticated()){
        return next();
    }
    res.redirect('/signin'); 
}

app.listen(4000, () => {
    console.log(`Server on localhost 4000`);
})