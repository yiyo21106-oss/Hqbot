const crypto = require("crypto");
const express = require("express");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

/*
  ==========================================
              HQBOT BACKEND
  ==========================================

  This is the first backend foundation for
  the Hqbot Minecraft bot dashboard.

  Website
      ↓
  Hqbot API
      ↓
  Bot Manager
      ↓
  Minecraft Bedrock bots

  Minecraft connection and automation will
  be added in the next stages.
*/

const bots = new Map();

/* ==========================================
   HOME / HEALTH CHECK
   ========================================== */

app.get("/", (req, res) => {
  res.json({
    name: "Hqbot",
    status: "online",
    message: "Hqbot backend is running"
  });
});

/* ==========================================
   GET ALL BOTS
   ========================================== */

app.get("/api/bots", (req, res) => {
  const botList = Array.from(bots.values()).map((bot) => ({
    id: bot.id,
    name: bot.name,
    status: bot.status,
    command: bot.command || null
  }));

  res.json(botList);
});

/* ==========================================
   CREATE A BOT
   ========================================== */

app.post("/api/bots", (req, res) => {
  const { name } = req.body;

  if (!name || typeof name !== "string") {
    return res.status(400).json({
      error: "Bot name is required"
    });
  }

  const id = crypto.randomUUID();

  const bot = {
    id: id,
    name: name.trim(),
    status: "offline",
    command: null
  };

  bots.set(id, bot);

  console.log(`Bot created: ${bot.name}`);

  res.json({
    success: true,
    bot: bot
  });
});

/* ==========================================
   SEND COMMAND TO A BOT
   ========================================== */

app.post("/api/bots/:id/command", (req, res) => {
  const bot = bots.get(req.params.id);
  const { command } = req.body;

  if (!bot) {
    return res.status(404).json({
      error: "Bot not found"
    });
  }

  if (!command || typeof command !== "string") {
    return res.status(400).json({
      error: "Command is required"
    });
  }

  bot.command = command.trim();

  console.log(`[${bot.name}] Command: ${bot.command}`);

  res.json({
    success: true,
    bot: bot.name,
    command: bot.command
  });
});

/* ==========================================
   DELETE A BOT
   ========================================== */

app.delete("/api/bots/:id", (req, res) => {
  const bot = bots.get(req.params.id);

  if (!bot) {
    return res.status(404).json({
      error: "Bot not found"
    });
  }

  bots.delete(req.params.id);

  console.log(`Bot deleted: ${bot.name}`);

  res.json({
    success: true,
    message: "Bot deleted"
  });
});

/* ==========================================
   START SERVER
   ========================================== */

app.listen(PORT, () => {
  console.log("================================");
  console.log("        HQBOT BACKEND");
  console.log("================================");
  console.log(`Server running on port ${PORT}`);
});
