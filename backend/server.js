const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const { Authflow } = require("prismarine-auth");
const bedrock = require("bedrock-protocol");

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

/* =========================================================
   DATA STORAGE
   ========================================================= */

const DATA_DIR = path.join(__dirname, "data");

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const USERS_FILE = path.join(DATA_DIR, "users.json");
const SESSIONS_FILE = path.join(DATA_DIR, "sessions.json");

function loadJSON(file, fallback) {
  try {
    if (!fs.existsSync(file)) {
      fs.writeFileSync(
        file,
        JSON.stringify(fallback, null, 2)
      );

      return fallback;
    }

    return JSON.parse(
      fs.readFileSync(file, "utf8")
    );
  } catch (error) {
    console.error("JSON load error:", error);
    return fallback;
  }
}

function saveJSON(file, data) {
  try {
    fs.writeFileSync(
      file,
      JSON.stringify(data, null, 2)
    );
  } catch (error) {
    console.error("JSON save error:", error);
  }
}

const users = new Map(
  Object.entries(
    loadJSON(USERS_FILE, {})
  )
);

const loginSessions = new Map(
  Object.entries(
    loadJSON(SESSIONS_FILE, {})
  )
);

const microsoftSessions = new Map();
const activeBots = new Map();

let activeActivationKey = null;

/* =========================================================
   PASSWORD SECURITY
   ========================================================= */

function hashPassword(password) {
  const salt =
    crypto.randomBytes(16).toString("hex");

  const hash =
    crypto
      .scryptSync(password, salt, 64)
      .toString("hex");

  return `${salt}:${hash}`;
}

function verifyPassword(
  password,
  storedPassword
) {
  try {
    const [salt, storedHash] =
      storedPassword.split(":");

    const hash =
      crypto
        .scryptSync(password, salt, 64)
        .toString("hex");

    return crypto.timingSafeEqual(
      Buffer.from(hash, "hex"),
      Buffer.from(storedHash, "hex")
    );
  } catch {
    return false;
  }
}

/* =========================================================
   LOGIN SYSTEM
   ========================================================= */

function saveSessions() {
  saveJSON(
    SESSIONS_FILE,
    Object.fromEntries(loginSessions)
  );
}

function createLoginToken(username) {
  const token =
    crypto.randomBytes(48).toString("hex");

  loginSessions.set(token, {
    username,
    createdAt: Date.now()
  });

  saveSessions();

  return token;
}

function getLoggedInUser(req) {
  const header =
    req.headers.authorization;

  if (
    !header ||
    !header.startsWith("Bearer ")
  ) {
    return null;
  }

  const token = header.slice(7);

  const session =
    loginSessions.get(token);

  if (!session) {
    return null;
  }

  return session.username;
}

function getLoginSession(req) {
  const header =
    req.headers.authorization;

  if (
    !header ||
    !header.startsWith("Bearer ")
  ) {
    return null;
  }

  const token = header.slice(7);

  const session =
    loginSessions.get(token);

  if (!session) {
    return null;
  }

  return {
    token,
    ...session
  };
}

/* =========================================================
   ACTIVATION KEYS
   ========================================================= */

function generateActivationKey() {
  return (
    "HQ-" +
    crypto
      .randomBytes(24)
      .toString("hex")
      .toUpperCase()
  );
}

/*
  Only ONE activation key can exist at a time.

  Example:

  {
    key: "HQ-XXXXXXXX",
    type: "monthly"
  }

  OR

  {
    key: "HQ-XXXXXXXX",
    type: "lifetime"
  }
*/

/* =========================================================
   PLAN SYSTEM
   ========================================================= */

function isPlanExpired(user) {
  if (!user) {
    return true;
  }

  if (user.plan === "lifetime") {
    return false;
  }

  if (user.plan === "monthly") {
    if (!user.expiresAt) {
      return true;
    }

    return Date.now() >= user.expiresAt;
  }

  return true;
}

function getRemainingMs(user) {
  if (!user) {
    return 0;
  }

  if (user.plan === "lifetime") {
    return null;
  }

  if (!user.expiresAt) {
    return 0;
  }

  return Math.max(
    0,
    user.expiresAt - Date.now()
  );
}

function requireActivePlan(req, res) {
  const username =
    getLoggedInUser(req);

  if (!username) {
    res.status(401).json({
      error: "You must login first."
    });

    return null;
  }

  const user =
    users.get(username);

  if (!user) {
    res.status(401).json({
      error: "Account not found."
    });

    return null;
  }

  if (isPlanExpired(user)) {
    res.status(403).json({
      error:
        "Error: Your Monthly Hqbot is expired."
    });

    return null;
  }

  return user;
}

/* =========================================================
   HOME
   ========================================================= */

app.get("/", (req, res) => {
  res.json({
    name: "Hqbot",
    status: "online"
  });
});

/* =========================================================
   REGISTER
   ========================================================= */

app.post(
  "/api/auth/register",
  (req, res) => {
    const {
      username,
      password,
      activationKey
    } = req.body;

    if (
      !username ||
      !password ||
      !activationKey
    ) {
      return res.status(400).json({
        error:
          "Username, password and activation key are required."
      });
    }

    if (users.has(username)) {
      return res.status(400).json({
        error:
          "Username already exists."
      });
    }

    if (!activeActivationKey) {
      return res.status(400).json({
        error:
          "No activation key is currently available."
      });
    }

    if (
      activationKey !==
      activeActivationKey.key
    ) {
      return res.status(400).json({
        error:
          "Invalid activation key."
      });
    }

    const plan =
      activeActivationKey.type;

    const now = Date.now();

    let expiresAt = null;

    if (plan === "monthly") {
      expiresAt =
        now +
        30 *
          24 *
          60 *
          60 *
          1000;
    }

    const user = {
      username,
      password:
        hashPassword(password),

      plan,

      activatedAt: now,

      expiresAt,

      createdAt: now
    };

    users.set(
      username,
      user
    );

    saveJSON(
      USERS_FILE,
      Object.fromEntries(users)
    );

    /*
      The activation key is consumed here.

      Monthly timer starts when the key
      is actually used.
    */

    activeActivationKey = null;

    const token =
      createLoginToken(username);

    res.json({
      success: true,
      message:
        "Account created successfully.",
      token,
      username,
      plan,
      expiresAt
    });
  }
);

/* =========================================================
   LOGIN
   ========================================================= */

app.post(
  "/api/auth/login",
  (req, res) => {
    const {
      username,
      password
    } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        error:
          "Username and password are required."
      });
    }

    const user =
      users.get(username);

    if (!user) {
      return res.status(401).json({
        error:
          "Invalid username or password."
      });
    }

    if (
      !verifyPassword(
        password,
        user.password
      )
    ) {
      return res.status(401).json({
        error:
          "Invalid username or password."
      });
    }

    /*
      No automatic session expiration.

      The user stays logged in until
      they press Logout.
    */

    const token =
      createLoginToken(username);

    res.json({
      success: true,
      message:
        "Login successful.",
      token,
      username,
      plan: user.plan,
      expiresAt: user.expiresAt
    });
  }
);

/* =========================================================
   LOGOUT
   ========================================================= */

app.post(
  "/api/auth/logout",
  (req, res) => {
    const session =
      getLoginSession(req);

    if (session) {
      loginSessions.delete(
        session.token
      );

      saveSessions();
    }

    res.json({
      success: true,
      message:
        "Logged out."
    });
  }
);

/* =========================================================
   CURRENT USER
   ========================================================= */

app.get(
  "/api/auth/me",
  (req, res) => {
    const username =
      getLoggedInUser(req);

    if (!username) {
      return res.status(401).json({
        error:
          "Not logged in."
      });
    }

    const user =
      users.get(username);

    if (!user) {
      return res.status(401).json({
        error:
          "Account not found."
      });
    }

    res.json({
      loggedIn: true,

      username,

      plan: user.plan,

      activatedAt:
        user.activatedAt,

      expiresAt:
        user.expiresAt,

      expired:
        isPlanExpired(user),

      remainingMs:
        getRemainingMs(user)
    });
  }
);

/* =========================================================
   PLAN
   ========================================================= */

app.get(
  "/api/plan",
  (req, res) => {
    const username =
      getLoggedInUser(req);

    if (!username) {
      return res.status(401).json({
        error:
          "Not logged in."
      });
    }

    const user =
      users.get(username);

    if (!user) {
      return res.status(404).json({
        error:
          "Account not found."
      });
    }

    const remainingMs =
      getRemainingMs(user);

    const remainingDays =
      remainingMs === null
        ? null
        : Math.ceil(
            remainingMs /
              (24 *
                60 *
                60 *
                1000)
          );

    res.json({
      username,

      plan:
        user.plan,

      activatedAt:
        user.activatedAt,

      expiresAt:
        user.expiresAt,

      expired:
        isPlanExpired(user),

      remainingMs,

      remainingDays
    });
  }
);

/* =========================================================
   ADMIN CHECK
   ========================================================= */

function checkAdmin(req, res) {
  const adminKey =
    req.headers["x-admin-key"];

  if (
    !process.env.HQBOT_ADMIN_KEY
  ) {
    res.status(500).json({
      error:
        "HQBOT_ADMIN_KEY is not configured."
    });

    return false;
  }

  if (
    adminKey !==
    process.env.HQBOT_ADMIN_KEY
  ) {
    res.status(403).json({
      error:
        "Unauthorized."
    });

    return false;
  }

  return true;
}

/* =========================================================
   ADMIN GENERATE KEY
   ========================================================= */

app.post(
  "/api/admin/generate-key",
  (req, res) => {
    if (!checkAdmin(req, res)) {
      return;
    }

    if (activeActivationKey) {
      return res.json({
        success: true,

        message:
          "An activation key is already active.",

        active: true,

        key:
          activeActivationKey.key,

        type:
          activeActivationKey.type
      });
    }

    const type =
      req.body.type;

    if (
      type !== "monthly" &&
      type !== "lifetime"
    ) {
      return res.status(400).json({
        error:
          "Type must be monthly or lifetime."
      });
    }

    const key =
      generateActivationKey();

    activeActivationKey = {
      key,
      type
    };

    res.json({
      success: true,

      message:
        "New activation key generated.",

      active: true,

      key,

      type
    });
  }
);

/* =========================================================
   ADMIN KEY STATUS
   ========================================================= */

app.get(
  "/api/admin/key-status",
  (req, res) => {
    if (!checkAdmin(req, res)) {
      return;
    }

    res.json({
      active:
        !!activeActivationKey,

      type:
        activeActivationKey
          ? activeActivationKey.type
          : null
    });
  }
);

/* =========================================================
   MICROSOFT / XBOX LOGIN
   ========================================================= */

app.post(
  "/api/microsoft/login",
  async (req, res) => {
    const user =
      requireActivePlan(
        req,
        res
      );

    if (!user) {
      return;
    }

    const sessionId =
      crypto.randomUUID();

    microsoftSessions.set(
      sessionId,
      {
        username:
          user.username,

        status:
          "starting",

        code: null,

        verificationUri:
          null,

        message: null,

        botStatus:
          "offline"
      }
    );

    res.json({
      sessionId,

      status:
        "starting"
    });

    try {
      const auth =
        new Authflow(
          `hqbot-${user.username}-${sessionId}`,

          "./auth-cache",

          undefined,

          (data) => {
            const session =
              microsoftSessions.get(
                sessionId
              );

            if (!session) {
              return;
            }

            session.code =
              data.user_code;

            session.verificationUri =
              data.verification_uri;

            session.message =
              data.message;

            session.status =
              "waiting_for_login";

            console.log(
              "Microsoft device code:",
              data.user_code
            );

            console.log(
              "Microsoft login:",
              data.verification_uri
            );
          }
        );

      await auth.getXboxToken();

      const session =
        microsoftSessions.get(
          sessionId
        );

      if (!session) {
        return;
      }

      session.status =
        "microsoft_connected";

      /*
        Connect to Lifeboat.
      */

      const host =
        process.env.LBSG_HOST;

      const port =
        Number(
          process.env.LBSG_PORT ||
            19132
        );

      if (!host) {
        session.status =
          "microsoft_connected";

        session.botStatus =
          "waiting_for_lifeboat";

        session.error =
          "LBSG_HOST is not configured.";

        console.error(
          "LBSG_HOST is not configured."
        );

        return;
      }

      console.log(
        `Connecting ${user.username} to Lifeboat: ${host}:${port}`
      );

      const bot =
        bedrock.createClient({
          host,

          port,

          authflow:
            auth,

          offline:
            false
        });

      activeBots.set(
        user.username,
        {
          bot,

          sessionId,

          username:
            user.username,

          connected:
            false,

          spawned:
            false,

          health:
            null,

          hunger:
            null,

          position:
            null,

          world:
            null
        }
      );

      /* =====================================================
         BOT CONNECT
         ===================================================== */

      bot.on(
        "connect",
        () => {
          console.log(
            `[${user.username}] Bot connected.`
          );

          const s =
            microsoftSessions.get(
              sessionId
            );

          if (s) {
            s.botStatus =
              "connected";
          }
        }
      );

      /* =====================================================
         BOT JOIN
         ===================================================== */

      bot.on(
        "join",
        () => {
          console.log(
            `[${user.username}] Bot joined.`
          );

          const s =
            microsoftSessions.get(
              sessionId
            );

          if (s) {
            s.botStatus =
              "joined";
          }
        }
      );

      /* =====================================================
         BOT SPAWN
         ===================================================== */

      bot.on(
        "spawn",
        () => {
          console.log(
            `[${user.username}] Bot spawned.`
          );

          const active =
            activeBots.get(
              user.username
            );

          if (active) {
            active.connected =
              true;

            active.spawned =
              true;
          }

          const s =
            microsoftSessions.get(
              sessionId
            );

          if (s) {
            s.status =
              "connected";

            s.botStatus =
              "online";
          }
        }
      );

      /* =====================================================
         BOT TEXT
         ===================================================== */

      bot.on(
        "text",
        (packet) => {
          console.log(
            `[${user.username}]`,
            packet
          );
        }
      );

      /* =====================================================
         BOT ERROR
         ===================================================== */

      bot.on(
        "error",
        (error) => {
          console.error(
            `[${user.username}] Bot error:`,
            error
          );

          const s =
            microsoftSessions.get(
              sessionId
            );

          if (s) {
            s.botStatus =
              "error";

            s.error =
              error.message ||
              String(error);
          }
        }
      );

      /* =====================================================
         BOT CLOSE
         ===================================================== */

      bot.on(
        "close",
        () => {
          console.log(
            `[${user.username}] Bot disconnected.`
          );

          const active =
            activeBots.get(
              user.username
            );

          if (active) {
            active.connected =
              false;

            active.spawned =
              false;
          }

          const s =
            microsoftSessions.get(
              sessionId
            );

          if (s) {
            s.botStatus =
              "offline";
          }
        }
      );

    } catch (error) {
      console.error(
        "Microsoft/Bot login error:",
        error
      );

      const session =
        microsoftSessions.get(
          sessionId
        );

      if (session) {
        session.status =
          "error";

        session.error =
          error.message ||
          String(error);
      }
    }
  }
);

/* =========================================================
   MICROSOFT LOGIN STATUS
   ========================================================= */

app.get(
  "/api/microsoft/login/:sessionId",
  (req, res) => {
    const username =
      getLoggedInUser(req);

    if (!username) {
      return res.status(401).json({
        error:
          "Not logged in."
      });
    }

    const session =
      microsoftSessions.get(
        req.params.sessionId
      );

    if (!session) {
      return res.status(404).json({
        error:
          "Login session not found."
      });
    }

    if (
      session.username !==
      username
    ) {
      return res.status(403).json({
        error:
          "Unauthorized."
      });
    }

    res.json(session);
  }
);

/* =========================================================
   BOT STATUS
   ========================================================= */

app.get(
  "/api/bot/status",
  (req, res) => {
    const user =
      requireActivePlan(
        req,
        res
      );

    if (!user) {
      return;
    }

    const active =
      activeBots.get(
        user.username
      );

    if (!active) {
      return res.json({
        online:
          false,

        status:
          "offline"
      });
    }

    res.json({
      online:
        active.connected === true,

      spawned:
        active.spawned === true,

      status:
        active.connected
          ? "online"
          : "offline",

      health:
        active.health,

      hunger:
        active.hunger,

      position:
        active.position,

      world:
        active.world
    });
  }
);

/* =========================================================
   BOT COMMAND
   ========================================================= */

app.post(
  "/api/bot/command",
  (req, res) => {
    const user =
      requireActivePlan(
        req,
        res
      );

    if (!user) {
      return;
    }

    const command =
      req.body.command;

    if (
      !command ||
      typeof command !==
        "string"
    ) {
      return res.status(400).json({
        error:
          "Command is required."
      });
    }

    const active =
      activeBots.get(
        user.username
      );

    if (
      !active ||
      !active.bot
    ) {
      return res.status(400).json({
        error:
          "Bot is not online."
      });
    }

    try {
      const message =
        command.startsWith("/")
          ? command
          : `/${command}`;

      active.bot.queue(
        "text",
        {
          type:
            "chat",

          needs_translation:
            false,

          source_name:
            "",

          message
        }
      );

      res.json({
        success:
          true,

        command
      });

    } catch (error) {
      res.status(500).json({
        error:
          error.message
      });
    }
  }
);

/* =========================================================
   DISCORD BOT
   ========================================================= */

const discordClient =
  new Client({
    intents: [
      GatewayIntentBits.Guilds
    ]
  });

const monthlyCommand =
  new SlashCommandBuilder()
    .setName(
      "genkeymonthly"
    )
    .setDescription(
      "Generate a 30-day Hqbot activation key"
    );

const lifetimeCommand =
  new SlashCommandBuilder()
    .setName(
      "genkeylifetime"
    )
    .setDescription(
      "Generate a lifetime Hqbot activation key"
    );

discordClient.once(
  "ready",
  async () => {
    console.log(
      `Discord bot logged in as ${discordClient.user.tag}`
    );

    try {
      const rest =
        new REST({
          version:
            "10"
        }).setToken(
          process.env.DISCORD_BOT_TOKEN
        );

      await rest.put(
        Routes.applicationCommands(
          discordClient.user.id
        ),
        {
          body: [
            monthlyCommand.toJSON(),
            lifetimeCommand.toJSON()
          ]
        }
      );

      console.log(
        "Discord key commands registered."
      );

    } catch (error) {
      console.error(
        "Discord command registration error:",
        error
      );
    }
  }
);

discordClient.on(
  "interactionCreate",
  async (interaction) => {
    if (
      !interaction.isChatInputCommand()
    ) {
      return;
    }

    if (
      interaction.commandName !==
        "genkeymonthly" &&
      interaction.commandName !==
        "genkeylifetime"
    ) {
      return;
    }

    /*
      Only one active key.
    */

    if (activeActivationKey) {
      return interaction.reply({
        content:
          `⚠️ An activation key is already active.\n\n` +
          `Type: **${activeActivationKey.type}**\n` +
          `Key: \`${activeActivationKey.key}\``,
        ephemeral:
          true
      });
    }

    const type =
      interaction.commandName ===
      "genkeymonthly"
        ? "monthly"
        : "lifetime";

    const key =
      generateActivationKey();

    activeActivationKey = {
      key,
      type
    };

    const description =
      type === "monthly"
        ? "30 days after activation"
        : "Never expires";

    await interaction.reply({
      content:
        `🔐 **Hqbot ${type} key**\n\n` +
        `\`${key}\`\n\n` +
        `⏳ ${description}`,
      ephemeral:
        true
    });

    console.log(
      `Generated ${type} activation key.`
    );
  }
);

if (
  process.env.DISCORD_BOT_TOKEN
) {
  discordClient
    .login(
      process.env.DISCORD_BOT_TOKEN
    )
    .catch((error) => {
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

/* =========================================================
   START SERVER
   ========================================================= */

app.listen(
  PORT,
  () => {
    console.log(
      `Hqbot backend running on port ${PORT}`
    );
  }
);
