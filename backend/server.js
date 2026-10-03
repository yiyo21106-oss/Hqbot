const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Authflow } = require("prismarine-auth");
const {
  Client,
  GatewayIntentBits,
  REST,
  Routes,
  SlashCommandBuilder
} = require("discord.js");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const users = new Map();
const loginSessions = new Map();
const microsoftSessions = new Map();

let activeActivationKey = null;

// =========================
// PASSWORD SECURITY
// =========================

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return `${salt}:${hash}`;
}

function verifyPassword(password, storedPassword) {
  const [salt, storedHash] = storedPassword.split(":");

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return crypto.timingSafeEqual(
    Buffer.from(hash, "hex"),
    Buffer.from(storedHash, "hex")
  );
}

// =========================
// LOGIN SESSIONS
// =========================

function createLoginToken(username) {
  const token = crypto.randomBytes(32).toString("hex");

  loginSessions.set(token, {
    username,
    createdAt: Date.now()
  });

  return token;
}

function getLoggedInUser(req) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return null;
  }

  const token = header.slice(7);
  const session = loginSessions.get(token);

  if (!session) {
    return null;
  }

  return session.username;
}

// =========================
// GENERATE ACTIVATION KEY
// =========================

function generateActivationKey() {
  if (activeActivationKey) {
    return activeActivationKey;
  }

  activeActivationKey =
    "HQ-" +
    crypto.randomBytes(24).toString("hex").toUpperCase();

  return activeActivationKey;
}

// =========================
// BASIC SERVER
// =========================

app.get("/", (req, res) => {
  res.json({
    name: "Hqbot",
    status: "online"
  });
});

// =========================
// REGISTER
// =========================

app.post("/api/auth/register", (req, res) => {
  const { username, password, activationKey } = req.body;

  if (!username || !password || !activationKey) {
    return res.status(400).json({
      error: "Username, password and activation key are required."
    });
  }

  if (users.has(username)) {
    return res.status(400).json({
      error: "Username already exists."
    });
  }

  if (!activeActivationKey) {
    return res.status(400).json({
      error: "No activation key is currently available."
    });
  }

  if (activationKey !== activeActivationKey) {
    return res.status(400).json({
      error: "Invalid activation key."
    });
  }

  users.set(username, {
    username,
    password: hashPassword(password),
    createdAt: Date.now()
  });

  // KEY IS CONSUMED
  activeActivationKey = null;

  const token = createLoginToken(username);

  res.json({
    success: true,
    message: "Account created successfully.",
    token,
    username
  });
});

// =========================
// LOGIN
// =========================

app.post("/api/auth/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      error: "Username and password are required."
    });
  }

  const user = users.get(username);

  if (!user) {
    return res.status(401).json({
      error: "Invalid username or password."
    });
  }

  if (!verifyPassword(password, user.password)) {
    return res.status(401).json({
      error: "Invalid username or password."
    });
  }

  const token = createLoginToken(username);

  res.json({
    success: true,
    message: "Login successful.",
    token,
    username
  });
});

// =========================
// LOGOUT
// =========================

app.post("/api/auth/logout", (req, res) => {
  const header = req.headers.authorization;

  if (header && header.startsWith("Bearer ")) {
    const token = header.slice(7);
    loginSessions.delete(token);
  }

  res.json({
    success: true
  });
});

// =========================
// CURRENT USER
// =========================

app.get("/api/auth/me", (req, res) => {
  const username = getLoggedInUser(req);

  if (!username) {
    return res.status(401).json({
      error: "Not logged in."
    });
  }

  res.json({
    loggedIn: true,
    username
  });
});

// =========================
// ADMIN KEY GENERATOR
// =========================

app.post("/api/admin/generate-key", (req, res) => {
  const adminKey = req.headers["x-admin-key"];

  if (!process.env.HQBOT_ADMIN_KEY) {
    return res.status(500).json({
      error: "HQBOT_ADMIN_KEY is not configured."
    });
  }

  if (adminKey !== process.env.HQBOT_ADMIN_KEY) {
    return res.status(403).json({
      error: "Unauthorized."
    });
  }

  if (activeActivationKey) {
    return res.json({
      success: true,
      message: "An activation key is already active.",
      active: true,
      key: activeActivationKey
    });
  }

  const key = generateActivationKey();

  res.json({
    success: true,
    message: "New activation key generated.",
    active: true,
    key
  });
});

// =========================
// ADMIN KEY STATUS
// =========================

app.get("/api/admin/key-status", (req, res) => {
  const adminKey = req.headers["x-admin-key"];

  if (!process.env.HQBOT_ADMIN_KEY) {
    return res.status(500).json({
      error: "HQBOT_ADMIN_KEY is not configured."
    });
  }

  if (adminKey !== process.env.HQBOT_ADMIN_KEY) {
    return res.status(403).json({
      error: "Unauthorized."
    });
  }

  res.json({
    active: !!activeActivationKey
  });
});

// =========================
// MICROSOFT / XBOX LOGIN
// =========================

app.post("/api/microsoft/login", async (req, res) => {
  const username = getLoggedInUser(req);

  if (!username) {
    return res.status(401).json({
      error: "You must login to Hqbot before adding a Microsoft account."
    });
  }

  const sessionId = crypto.randomUUID();

  microsoftSessions.set(sessionId, {
    username,
    status: "waiting",
    code: null,
    verificationUri: null
  });

  res.json({
    sessionId,
    status: "starting"
  });

  try {
    const auth = new Authflow(
      `hqbot-${sessionId}`,
      "./auth-cache",
      undefined,
      (data) => {
        const session = microsoftSessions.get(sessionId);

        if (!session) return;

        session.code = data.user_code;
        session.verificationUri = data.verification_uri;
        session.message = data.message;
        session.status = "waiting_for_login";

        console.log(
          "Microsoft device code:",
          data.user_code
        );

        console.log(
          "Login:",
          data.verification_uri
        );
      }
    );

    await auth.getXboxToken();

    const session = microsoftSessions.get(sessionId);

    if (session) {
      session.status = "connected";
    }
  } catch (error) {
    console.error(
      "Microsoft login error:",
      error
    );

    const session = microsoftSessions.get(sessionId);

    if (session) {
      session.status = "error";
      session.error = error.message;
    }
  }
});

// =========================
// MICROSOFT LOGIN STATUS
// =========================

app.get(
  "/api/microsoft/login/:sessionId",
  (req, res) => {
    const username = getLoggedInUser(req);

    if (!username) {
      return res.status(401).json({
        error: "Not logged in."
      });
    }

    const session =
      microsoftSessions.get(req.params.sessionId);

    if (!session) {
      return res.status(404).json({
        error: "Login session not found."
      });
    }

    if (session.username !== username) {
      return res.status(403).json({
        error: "Unauthorized."
      });
    }

    res.json(session);
  }
);

// =========================
// DISCORD BOT
// =========================

const discordClient = new Client({
  intents: [
    GatewayIntentBits.Guilds
  ]
});

const genkeyCommand = new SlashCommandBuilder()
  .setName("genkey")
  .setDescription("Generate an Hqbot activation key");

discordClient.once("ready", async () => {
  console.log(
    `Discord bot logged in as ${discordClient.user.tag}`
  );

  try {
    const rest = new REST({ version: "10" })
      .setToken(process.env.DISCORD_BOT_TOKEN);

    await rest.put(
      Routes.applicationCommands(discordClient.user.id),
      {
        body: [
          genkeyCommand.toJSON()
        ]
      }
    );

    console.log(
      "Discord /genkey command registered."
    );
  } catch (error) {
    console.error(
      "Discord command registration error:",
      error
    );
  }
});

discordClient.on("interactionCreate", async (interaction) => {
  if (!interaction.isChatInputCommand()) {
    return;
  }

  if (interaction.commandName !== "genkey") {
    return;
  }

  const key = generateActivationKey();

  await interaction.reply({
    content:
      `🔐 Hqbot Activation Key:\n\`${key}\``,
    ephemeral: true
  });
});

if (process.env.DISCORD_BOT_TOKEN) {
  discordClient.login(
    process.env.DISCORD_BOT_TOKEN
  ).catch((error) => {
    console.error(
      "Discord login failed:",
      error
    );
  });
} else {
  console.log(
    "DISCORD_BOT_TOKEN is not configured."
  );
}

// =========================
// START SERVER
// =========================

app.listen(PORT, () => {
  console.log(
    `Hqbot backend running on port ${PORT}`
  );
});
