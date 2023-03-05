const express = require("express");
const bcrypt = require("bcrypt");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const { PrismaClient } = require("@prisma/client");
const prisma = new PrismaClient();
const app = express();
var cors = require("cors");

//app.use(cors());
app.use(cors({ credentials: true, origin: "http://localhost:3001" }));
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const users = [
  {
    name: "taher",
    password: "password",
  },
];

app.get("/users", authenticateToken, (req, res) => {
  res.json(req.user);
});

app.post("/create_user", async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = await prisma.user.create({
      data: {
        name: req.body.name,
        password: hashedPassword,
      },
    });
    res.json(user);
  } catch (e) {
    res.send(e);
  }
});

app.post("/user/login", async (req, res) => {
  try {
    const user = await prisma.user.findFirst({
      where: {
        name: req.body.name,
      },
    });
    if (user) {
      if (await bcrypt.compare(req.body.password, user.password)) {
        //res.send("success");
        const accessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);
        res.json({ acessToken: accessToken });
      } else {
        res.send("Not Allowed");
      }
    } else {
      res.send("User Not Found");
    }
  } catch (e) {
    res.send(e);
  }
});

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  // const token = req.cookies._auth;
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) return res.send("no token");

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.send("token is invalid");
    req.user = user;
    next();
  });
}

app.listen(3000);
