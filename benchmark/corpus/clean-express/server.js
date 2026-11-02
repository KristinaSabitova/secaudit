const express = require("express");
const { execFile } = require("child_process");
const path = require("path");
const app = express();
const ROOT = path.resolve("public");

app.get("/item", (req, res) => {
  const id = Number(req.params.id);
  db.query("SELECT * FROM items WHERE id = ?", [id]);
});

app.get("/download", (req, res) => {
  const name = path.basename(String(req.query.file));
  res.sendFile(name, { root: ROOT });
});

app.get("/echo", (req, res) => {
  res.json({ q: String(req.query.q) });
});

app.listen(3000);
