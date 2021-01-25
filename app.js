const express = require("express");
const cors = require("cors");
const config = require("config");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");

const app = express();

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: false }));

// parse application/json
app.use(bodyParser.json());

app.use(cors());

app.use(express.json({ extended: true }));

app.use("/api/auth", require("./routes/auth.routes"));

const PORT = process.env.port || 5000;

async function start() {
  try {
    await mongoose.connect(config.get("url"), {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    app.listen(PORT, () => console.log("App has been started on port" + PORT));
  } catch (e) {
    console.log("Server error", e.message);
    process.exit(1);
  }
}

start();
