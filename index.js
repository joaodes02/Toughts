const express = require("express");
const exphbs = require("express-handlebars");
const session = require("express-session");
const FileStore = require("session-file-store")(session);
const flash = require("express-flash");
const path = require("path");
const sessionPath = path.join(__dirname, "sessions");

const app = express();

const conn = require("./db/conn");

//Models
const Tought = require("./models/Toughts");
const User = require("./models/User");
const { FORCE } = require("sequelize/lib/index-hints");

// Import Routes
const toughtsRoutes = require("./routes/toughtsRoutes");
const authRoutes = require("./routes/authRoutes");

//Import Controller
const ToughtController = require("./controllers/ToughtController");

//template engine
app.engine("handlebars", exphbs.engine());
app.set("view engine", "handlebars");

//receber resposta do body
app.use(
  express.urlencoded({
    extended: true,
  })
);
app.use(express.json());

//middleware
app.use(
  session({
    name: "session",
    secret: "nosso_secret",
    resave: false,
    saveUninitialized: false,
    store: new FileStore({
      logFn: function () {},
      path: sessionPath,
    }),
    cookie: {
      secure: false,
      maxAge: 360000,
      expires: new Date(Date.now() + 360000),
      httpOnly: true,
    },
  })
);

// Flash Messages
app.use(flash());

// public path
app.use(express.static("public"));

//set session to res
app.use((req, res, next) => {
  if (req.session.userid) {
    res.locals.session = req.session;
  }

  next();
});

// Routes
app.use("/toughts", toughtsRoutes);
app.get("/", ToughtController.showToughts);
app.use("/", authRoutes);

conn
  .sync()
  // .sync({ force: true })
  .then(() => {
    app.listen(3000);
  })
  .catch((err) => console.log(err));
