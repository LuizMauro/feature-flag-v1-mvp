const express = require("express");
const bodyParser = require("body-parser");
const sqlite3 = require("sqlite3").verbose();
const crypto = require("crypto");

const app = express();
const db = new sqlite3.Database(":memory:"); // Use um arquivo SQLite em produção

app.use(bodyParser.json());

// Criar tabelas no banco de dados
db.serialize(() => {
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      public_key TEXT NOT NULL UNIQUE,
      secret_key TEXT NOT NULL UNIQUE,
      role TEXT DEFAULT 'user'
    )
  `);

  db.run(`
    CREATE TABLE flags (
      id INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      description TEXT,
      is_active INTEGER DEFAULT 0,
      environment TEXT NOT NULL,
      segment_type TEXT,
      segment_value TEXT,
      user_id INTEGER NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);
});

// Middleware para autenticação com chave pública ou secreta
function authenticateKey(req, res, next) {
  const authHeader = req.headers["authorization"];
  const key = authHeader && authHeader.split(" ")[1]; // Formato: Bearer <key>

  if (!key) {
    return res
      .status(401)
      .json({ success: false, message: "Chave não fornecida." });
  }

  // Verifica se a chave é pública ou secreta
  db.get(
    "SELECT * FROM users WHERE public_key = ? OR secret_key = ?",
    [key, key],
    (err, user) => {
      if (!user) {
        return res
          .status(403)
          .json({ success: false, message: "Chave inválida." });
      }

      // Adiciona o usuário e o tipo de chave à requisição
      req.user = user;
      req.keyType = user.public_key === key ? "public" : "secret";
      next();
    }
  );
}

// Gerar chaves públicas e secretas
function generateKeys() {
  return {
    publicKey: crypto.randomBytes(16).toString("hex"), // Chave pública
    secretKey: crypto.randomBytes(32).toString("hex"), // Chave secreta
  };
}

// Rota para criar um novo usuário
app.post("/users", (req, res) => {
  const { name } = req.body;
  const { publicKey, secretKey } = generateKeys();

  db.run(
    "INSERT INTO users (name, public_key, secret_key) VALUES (?, ?, ?)",
    [name, publicKey, secretKey],
    function (err) {
      if (err) {
        return res
          .status(500)
          .json({ success: false, message: "Erro ao criar usuário." });
      }
      res.json({ id: this.lastID, name, publicKey, secretKey });
    }
  );
});

// Listar todas as flags do usuário (requer chave pública)
app.get("/flags", authenticateKey, (req, res) => {
  if (req.keyType !== "public") {
    return res
      .status(403)
      .json({
        success: false,
        message: "Acesso negado. Use uma chave pública.",
      });
  }

  const userId = req.user.id; // ID do usuário autenticado

  db.all("SELECT * FROM flags WHERE user_id = ?", [userId], (err, rows) => {
    res.json(rows);
  });
});

// Criar uma nova flag (requer chave secreta)
app.post("/flags", authenticateKey, (req, res) => {
  if (req.keyType !== "secret") {
    return res
      .status(403)
      .json({
        success: false,
        message: "Acesso negado. Use uma chave secreta.",
      });
  }

  const {
    name,
    description,
    is_active,
    environment,
    segment_type,
    segment_value,
  } = req.body;
  const userId = req.user.id; // ID do usuário autenticado

  db.run(
    "INSERT INTO flags (name, description, is_active, environment, segment_type, segment_value, user_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [
      name,
      description,
      is_active,
      environment,
      segment_type,
      segment_value,
      userId,
    ],
    function (err) {
      if (err) {
        return res
          .status(500)
          .json({ success: false, message: "Erro ao criar flag." });
      }
      res.json({ id: this.lastID });
    }
  );
});

// Verificar o status de uma flag do usuário (requer chave pública)
app.get("/flags/check", authenticateKey, (req, res) => {
  if (req.keyType !== "public") {
    return res
      .status(403)
      .json({
        success: false,
        message: "Acesso negado. Use uma chave pública.",
      });
  }

  const { flag_name, environment, segment_type, segment_value } = req.query;
  const userId = req.user.id; // ID do usuário autenticado

  let query =
    "SELECT * FROM flags WHERE name = ? AND environment = ? AND user_id = ?";
  let params = [flag_name, environment, userId];

  if (segment_type && segment_value) {
    query += " AND segment_type = ? AND segment_value = ?";
    params.push(segment_type, segment_value);
  } else {
    query += " AND segment_type = 'all'";
  }

  db.get(query, params, (err, row) => {
    if (row) {
      res.json({ is_active: row.is_active });
    } else {
      res.json({ is_active: false });
    }
  });
});

// Atualizar uma flag existente do usuário (requer chave secreta)
app.put("/flags/:id", authenticateKey, (req, res) => {
  if (req.keyType !== "secret") {
    return res
      .status(403)
      .json({
        success: false,
        message: "Acesso negado. Use uma chave secreta.",
      });
  }

  const { id } = req.params;
  const {
    name,
    description,
    is_active,
    environment,
    segment_type,
    segment_value,
  } = req.body;
  const userId = req.user.id; // ID do usuário autenticado

  db.run(
    "UPDATE flags SET name = ?, description = ?, is_active = ?, environment = ?, segment_type = ?, segment_value = ? WHERE id = ? AND user_id = ?",
    [
      name,
      description,
      is_active,
      environment,
      segment_type,
      segment_value,
      id,
      userId,
    ],
    function (err) {
      if (this.changes > 0) {
        res.json({ success: true, message: "Flag atualizada com sucesso!" });
      } else {
        res
          .status(404)
          .json({
            success: false,
            message:
              "Flag não encontrada ou você não tem permissão para editá-la.",
          });
      }
    }
  );
});

// Excluir uma flag do usuário (requer chave secreta)
app.delete("/flags/:id", authenticateKey, (req, res) => {
  if (req.keyType !== "secret") {
    return res
      .status(403)
      .json({
        success: false,
        message: "Acesso negado. Use uma chave secreta.",
      });
  }

  const { id } = req.params;
  const userId = req.user.id; // ID do usuário autenticado

  db.run(
    "DELETE FROM flags WHERE id = ? AND user_id = ?",
    [id, userId],
    function (err) {
      if (this.changes > 0) {
        res.json({ success: true, message: "Flag excluída com sucesso!" });
      } else {
        res
          .status(404)
          .json({
            success: false,
            message:
              "Flag não encontrada ou você não tem permissão para excluí-la.",
          });
      }
    }
  );
});

// Iniciar o servidor
app.listen(3000, () => {
  console.log("Servidor rodando na porta 3000");
});
