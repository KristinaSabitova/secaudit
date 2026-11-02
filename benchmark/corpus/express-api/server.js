const express = require("express");
const { exec } = require("child_process");
const app = express();

app.get("/ls", (req, res) => {
  const dir = req.query.dir;
  exec("ls -la " + dir, (err, out) => res.type("text").end(String(out)));
});

app.get("/item", (req, res) => {
  const id = req.params.id;
  db.query(`SELECT * FROM items WHERE id = ${id}`);
});

app.get("/item/safe", (req, res) => {
  const id = req.params.id;
  db.query("SELECT * FROM items WHERE id = ?", [id]);
});

app.get("/download", (req, res) => {
  const file = req.query.file;
  res.sendFile(file);
});

app.get("/out", (req, res) => {
  const to = req.query.to;
  res.redirect(to);
});

app.get("/echo", (req, res) => {
  const q = req.query.q;
  res.send("<p>" + q + "</p>");
});

app.get("/proxy", (req, res) => {
  const u = req.query.u;
  fetch(u).then((r) => r.text()).then((t) => res.type("text").end(t));
});

app.post("/calc", (req, res) => {
  const expr = req.body.expr;
  eval(expr);
});

app.listen(3000);
