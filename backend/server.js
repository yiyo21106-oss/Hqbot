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

const DATA_DIR = process.env.DATA_DIR || "/data";

try {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
} catch (err) {
  console.error("Could not create DATA_DIR:", err);
}

/*
  These files are stored in /data.

  IMPORTANT:
  Railway must have a Volume mounted at /data
  if you want accounts to survive redeploys/restarts.
*/

const USERS_FILE = path.join(DATA_DIR, "users.json");
const SESSIONS_FILE = path.join(DATA_DIR, "sessions.json");
const KEYS_FILE = path.join(DATA_DIR, "keys.json");

function loadJSON(file, fallback) {
  try {
    if (!fs.existsSync(file)) {
      fs.writeFileSync(
        file,
        JSON.stringify(fallback, null, 2),
        "utf8"
      );

      return fallback;
    }

    const raw = fs.readFileSync(file, "utf8");

    if (!raw.trim()) {
      return fallback;
    }

    return JSON.parse(raw);
  } catch (error) {
    console.error("JSON load error:", file, error);
    return fallback;
  }
}

function saveJSON(file, data) {
  try {
    const tempFile = `${file}.tmp`;

    fs.writeFileSync(
      tempFile,
      JSON.stringify(data, null, 2),
      "utf8"
    );

    fs.renameSync(tempFile, file);

    return true;
  } catch (error) {
    console.error("JSON save error:", file, error);
    return false;
  }
}

const users = new Map(
  Object.entries(loadJSON(USERS_FILE, {}))
);

const loginSessions = new Map(
  Object.entries(loadJSON(SESSIONS_FILE, {}))
);

const activationKeys = new Map(
  Object.entries(loadJSON(KEYS_FILE, {}))
);

const microsoftSessions = new Map();
const activeBots = new Map();

/* =========================================================
   PASSWORDS
   ========================================================= */

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString("hex");

  return `${salt}:${hash}`;
}

function verifyPassword(password, storedPassword) {
  try {
    if (!storedPassword || !storedPassword.includes(":")) {
      return false;
    }

    const [salt, storedHash] = storedPassword.split(":");

    const hash = crypto
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
   NORMALIZATION
   ========================================================= */

function normalizeActivationKey(value) {
  return String(value || "")
    .trim()
    .toUpperCase();
}

function normalizeUsername(value) {
  return String(value || "").trim();
}

/* =========================================================
   SESSIONS
   ========================================================= */

function saveSessions() {
  saveJSON(
    SESSIONS_FILE,
    Object.fromEntries(loginSessions)
  );
}

function createLoginToken(username) {
  const token = crypto
    .randomBytes(48)
    .toString("hex");

  loginSessions.set(token, {
    username,
    createdAt: Date.now()
  });

  saveSessions();

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

function getLoginSession(req) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return null;
  }

  const token = header.slice(7);

  const session = loginSessions.get(token);

  if (!session) {
    return null;
  }

  return {
    token,
    ...session
  };
}

/* =========================================================
   PLANS
   ========================================================= */

function isPlanExpired(user) {
  if (!user) return true;

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
  const username = getLoggedInUser(req);

  if (!username) {
    res.status(401).json({
      error: "You must login first."
    });

    return null;
  }

  const user = users.get(username);

  if (!user) {
    res.status(401).json({
      error: "Account not found."
    });

    return null;
  }

  if (isPlanExpired(user)) {
    res.status(403).json({
      error: "Error: Your Monthly Hqbot is expired."
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

app.post("/api/auth/register", (req, res) => {
  try {
    const username = normalizeUsername(req.body.username);
    const password = String(req.body.password || "");
    const activationKey = normalizeActivationKey(
      req.body.activationKey
    );

    if (!username || !password || !activationKey) {
      return res.status(400).json({
        error:
          "Username, password and activation key are required."
      });
    }

    if (username.length < 3) {
      return res.status(400).json({
        error: "Username must be at least 3 characters."
      });
    }

    if (password.length < 4) {
      return res.status(400).json({
        error: "Password must be at least 4 characters."
      });
    }

    if (users.has(username)) {
      return res.status(400).json({
        error: "Username already exists."
      });
    }

    const keyData = activationKeys.get(
      activationKey
    );

    if (!keyData) {
      return res.status(400).json({
        error: "Invalid activation key."
      });
    }

    const plan = keyData.type;

    if (
      plan !== "monthly" &&
      plan !== "lifetime"
    ) {
      return res.status(400).json({
        error: "Invalid activation key type."
      });
    }

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
      password: hashPassword(password),
      plan,
      activatedAt: now,
      expiresAt,
      createdAt: now
    };

    users.set(username, user);

    const saved = saveJSON(
      USERS_FILE,
      Object.fromEntries(users)
    );

    if (!saved) {
      users.delete(username);

      return res.status(500).json({
        error:
          "Could not save your account. Please try again."
      });
    }

    activationKeys.delete(activationKey);

    saveJSON(
      KEYS_FILE,
      Object.fromEntries(activationKeys)
    );

    const token = createLoginToken(username);

    res.json({
      success: true,
      message: "Account created successfully.",
      token,
      username,
      plan,
      expiresAt
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      error: "Registration failed."
    });
  }
});

/* =========================================================
   LOGIN
   ========================================================= */

app.post("/api/auth/login", (req, res) => {
  try {
    const username = normalizeUsername(
      req.body.username
    );

    const password = String(
      req.body.password || ""
    );

    if (!username || !password) {
      return res.status(400).json({
        error:
          "Username and password are required."
      });
    }

    const user = users.get(username);

    if (!user) {
      console.log(
        `LOGIN FAILED: user "${username}" does not exist.`
      );

      return res.status(401).json({
        error:
          "Invalid username or password."
      });
    }

    if (
      !user.password ||
      !verifyPassword(
        password,
        user.password
      )
    ) {
      console.log(
        `LOGIN FAILED: wrong password for "${username}".`
      );

      return res.status(401).json({
        error:
          "Invalid username or password."
      });
    }

    const token = createLoginToken(username);

    console.log(
      `LOGIN SUCCESS: ${username}`
    );

    res.json({
      success: true,
      message: "Login successful.",
      token,
      username,
      plan: user.plan,
      expiresAt: user.expiresAt
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      error: "Login failed."
    });
  }
});

/* =========================================================
   LOGOUT
   ========================================================= */

app.post("/api/auth/logout", (req, res) => {
  const session = getLoginSession(req);

  if (session) {
    loginSessions.delete(session.token);
    saveSessions();
  }

  res.json({
    success: true,
    message: "Logged out."
  });
});

/* =========================================================
   CURRENT USER
   ========================================================= */

app.get("/api/auth/me", (req, res) => {
  const username = getLoggedInUser(req);

  if (!username) {
    return res.status(401).json({
      error: "Not logged in."
    });
  }

  const user = users.get(username);

  if (!user) {
    return res.status(401).json({
      error: "Account not found."
    });
  }

  res.json({
    loggedIn: true,
    username,
    plan: user.plan,
    activatedAt: user.activatedAt,
    expiresAt: user.expiresAt,
    expired: isPlanExpired(user),
    remainingMs: getRemainingMs(user)
  });
});

/* =========================================================
   PLAN
   ========================================================= */

app.get("/api/plan", (req, res) => {
  const username = getLoggedInUser(req);

  if (!username) {
    return res.status(401).json({
      error: "Not logged in."
    });
  }

  const user = users.get(username);

  if (!user) {
    return res.status(404).json({
      error: "Account not found."
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
    plan: user.plan,
    activatedAt: user.activatedAt,
    expiresAt: user.expiresAt,
    expired: isPlanExpired(user),
    remainingMs,
    remainingDays
  });
});

/* =========================================================
   ADMIN
   ========================================================= */

function checkAdmin(req, res) {
  const adminKey =
    req.headers["x-admin-key"];

  if (!process.env.HQBOT_ADMIN_KEY) {
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
      error: "Unauthorized."
    });

    return false;
  }

  return true;
}

/* =========================================================
   ADMIN GENERATE KEY
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

function saveActivationKeys() {
  return saveJSON(
    KEYS_FILE,
    Object.fromEntries(activationKeys)
  );
}

app.post(
  "/api/admin/generate-key",
  (req, res) => {
    if (!checkAdmin(req, res)) {
      return;
    }

    const type = req.body.type;

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

    activationKeys.set(key, {
      type,
      createdAt: Date.now()
    });

    const saved =
      saveActivationKeys();

    if (!saved) {
      activationKeys.delete(key);

      return res.status(500).json({
        error:
          "Could not save activation key."
      });
    }

    res.json({
      success: true,
      message:
        "New activation key generated.",
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

    const keys =
      Array.from(
        activationKeys.entries()
      ).map(
        ([key, data]) => ({
          key,
          type: data.type,
          createdAt:
            data.createdAt
        })
      );

    res.json({
      active: keys.length > 0,
      total: keys.length,
      keys
    });
  }
);

/* =========================================================
   BOT STATE
   ========================================================= */

function getBotForUser(username) {
  return activeBots.get(username);
}

/* =========================================================
   BOT STATUS
   ========================================================= */

app.get(
  "/api/bot/status",
  (req, res) => {
    const user =
      requireActivePlan(req, res);

    if (!user) return;

    const bot =
      getBotForUser(
        user.username
      );

    if (!bot) {
      return res.json({
        online: false,
        status: "offline",
        health: null,
        hunger: null,
        position: null,
        world: null
      });
    }

    res.json({
      online:
        !!bot.connected,
      status:
        bot.status || "offline",
      health:
        bot.health ?? null,
      hunger:
        bot.hunger ?? null,
      position:
        bot.position ?? null,
      world:
        bot.world ?? null
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
      requireActivePlan(req, res);

    if (!user) return;

    const command =
      String(
        req.body.command || ""
      ).trim();

    if (!command) {
      return res.status(400).json({
        error: "Command is required."
      });
    }

    const bot =
      getBotForUser(
        user.username
      );

    if (
      !bot ||
      !bot.client ||
      !bot.connected
    ) {
      return res.status(400).json({
        error: "Bot is not connected."
      });
    }

    let finalCommand =
      command;

    if (
      !finalCommand.startsWith("/")
    ) {
      finalCommand =
        "/" + finalCommand;
    }

    try {
      bot.client.queue(
        "text",
        {
          type: "chat",
          needs_translation: false,
          source_name:
            bot.client.username || "",
          xuid: "",
          platform_chat_id: "",
          message: finalCommand
        }
      );

      res.json({
        success: true,
        message:
          "Command sent."
      });
    } catch (error) {
      console.error(
        "COMMAND ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Could not send command."
      });
    }
  }
);

/* =========================================================
   INVENTORY HELPERS
   ========================================================= */

function isNonEmptyItem(item) {
  if (!item) return false;

  if (
    item.id !== undefined &&
    item.id !== null &&
    Number(item.id) !== 0
  ) {
    return true;
  }

  if (
    item.item_id !== undefined &&
    item.item_id !== null &&
    Number(item.item_id) !== 0
  ) {
    return true;
  }

  if (item.name) {
    return true;
  }

  return false;
}

function getItemCount(item) {
  if (!item) return 0;

  if (
    typeof item.count === "number"
  ) {
    return item.count;
  }

  if (
    typeof item.stack_size ===
      "number"
  ) {
    return item.stack_size;
  }

  return 1;
}

function getItemStackId(item) {
  if (!item) return null;

  return (
    item.id ??
    item.item_id ??
    item.name ??
    null
  );
}

function normalizeInventoryItem(
  item,
  slot
) {
  if (!item) {
    return {
      slot,
      empty: true
    };
  }

  return {
    slot,
    empty:
      !isNonEmptyItem(item),
    id:
      item.id ??
      item.item_id ??
      null,
    name:
      item.name ??
      null,
    count:
      getItemCount(item),
    stackId:
      getItemStackId(item)
  };
}

/* =========================================================
   INVENTORY LISTENERS
   ========================================================= */

function attachInventoryListeners(
  username,
  bot
) {
  if (!bot.client) return;

  bot.inventory = Array(36)
    .fill(null);

  bot.client.on(
    "inventory_content",
    packet => {
      try {
        if (
          packet.window_id !== 0
        ) {
          return;
        }

        const contents =
          packet.input ?? [];

        for (
          let i = 0;
          i < 36;
          i++
        ) {
          bot.inventory[i] =
            contents[i] ?? null;
        }
      } catch (error) {
        console.error(
          "Inventory content error:",
          error
        );
      }
    }
  );

  bot.client.on(
    "inventory_slot",
    packet => {
      try {
        if (
          packet.window_id !== 0
        ) {
          return;
        }

        const slot =
          Number(packet.slot);

        if (
          slot >= 0 &&
          slot <= 35
        ) {
          bot.inventory[slot] =
            packet.item ?? null;
        }
      } catch (error) {
        console.error(
          "Inventory slot error:",
          error
        );
      }
    }
  );
}

/* =========================================================
   GET INVENTORY
   ========================================================= */

app.get(
  "/api/bot/inventory",
  (req, res) => {
    const user =
      requireActivePlan(req, res);

    if (!user) return;

    const bot =
      getBotForUser(
        user.username
      );

    if (
      !bot ||
      !bot.connected
    ) {
      return res.status(400).json({
        error: "Bot is not connected."
      });
    }

    const inventory =
      bot.inventory ||
      Array(36).fill(null);

    const hotbar =
      inventory
        .slice(0, 9)
        .map(
          (item, slot) =>
            normalizeInventoryItem(
              item,
              slot
            )
        );

    const mainInventory =
      inventory
        .slice(9, 36)
        .map(
          (item, index) =>
            normalizeInventoryItem(
              item,
              index + 9
            )
        );

    res.json({
      success: true,
      hotbar,
      mainInventory
    });
  }
);

/* =========================================================
   DROP INVENTORY ITEM
   ========================================================= */

app.post(
  "/api/bot/inventory/drop",
  async (req, res) => {
    const user =
      requireActivePlan(req, res);

    if (!user) return;

    const bot =
      getBotForUser(
        user.username
      );

    if (
      !bot ||
      !bot.connected ||
      !bot.client
    ) {
      return res.status(400).json({
        error:
          "Bot is not connected."
      });
    }

    const requestedSlot =
      Number(req.body.slot);

    if (
      !Number.isInteger(
        requestedSlot
      )
    ) {
      return res.status(400).json({
        error: "Invalid slot."
      });
    }

    /*
      HOTBAR PROTECTION

      Slots 0-8 are NEVER allowed.
      Main inventory is 9-35.
    */

    if (
      requestedSlot < 9 ||
      requestedSlot > 35
    ) {
      return res.status(400).json({
        error:
          "Hotbar slots are protected. Only main inventory slots can be dropped."
      });
    }

    const item =
      bot.inventory?.[
        requestedSlot
      ];

    if (
      !isNonEmptyItem(item)
    ) {
      return res.status(400).json({
        error:
          "That inventory slot is empty."
      });
    }

    try {
      /*
        Bedrock item stack request.
        This keeps the hotbar protected and
        only allows main inventory slots.
      */

      bot.client.queue(
        "item_stack_request",
        {
          request_id:
            Math.floor(
              Math.random() *
                2147483647
            ),
          actions: [],
          result: 0,
          type_id: "drop"
        }
      );

      /*
        Some Bedrock versions require
        additional transaction data.

        We intentionally do not touch slots
        0-8 here.
      */

      res.json({
        success: true,
        message:
          "Drop request sent."
      });
    } catch (error) {
      console.error(
        "DROP ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Could not drop item."
      });
    }
  }
);

/* =========================================================
   MICROSOFT LOGIN
   ========================================================= */

app.post(
  "/api/microsoft/login",
  async (req, res) => {
    const user =
      requireActivePlan(req, res);

    if (!user) return;

    const username =
      user.username;

    const sessionId =
      crypto.randomUUID();

    microsoftSessions.set(
      sessionId,
      {
        username,
        status: "starting",
        botStatus: "offline",
        createdAt: Date.now(),
        message: null,
        user_code: null,
        verification_uri: null
      }
    );

    try {
      const auth = new Authflow(
        `hqbot-${username}-${sessionId}`,
        "./auth-cache",
        undefined,
        message => {
          console.log(
            "Microsoft auth:",
            message
          );

          const session =
            microsoftSessions.get(
              sessionId
            );

          if (!session) return;

          session.message =
            String(message);

          /*
            Try to extract device code
            URL information from authflow text.
          */

          const codeMatch =
            String(message).match(
              /(?:code|Code)[\s:]+([A-Z0-9-]{4,})/
            );

          const urlMatch =
            String(message).match(
              /https?:\/\/[^\s]+/
            );

          if (codeMatch) {
            session.user_code =
              codeMatch[1];
          }

          if (urlMatch) {
            session.verification_uri =
              urlMatch[0];
          }

          microsoftSessions.set(
            sessionId,
            session
          );
        }
      );

      const session =
        microsoftSessions.get(
          sessionId
        );

      if (session) {
        session.status =
          "authenticating";
      }

      await auth.getXboxToken();

      const latestSession =
        microsoftSessions.get(
          sessionId
        );

      if (latestSession) {
        latestSession.status =
          "connecting";
      }

      const host =
        process.env.LBSG_HOST;

      const port =
        Number(
          process.env.LBSG_PORT ||
            19132
        );

      if (!host) {
        throw new Error(
          "LBSG_HOST is not configured."
        );
      }

      const client =
        bedrock.createClient({
          host,
          port,
          authflow: auth,
          offline: false
        });

      const bot = {
        client,
        username,
        connected: false,
        spawned: false,
        status: "connecting",
        health: null,
        hunger: null,
        position: null,
        world: null,
        inventory:
          Array(36).fill(null)
      };

      activeBots.set(
        username,
        bot
      );

      attachInventoryListeners(
        username,
        bot
      );

      client.on(
        "connect",
        () => {
          console.log(
            `Bot connected for ${username}`
          );

          bot.connected = true;
          bot.status =
            "connected";
        }
      );

      client.on(
        "join",
        () => {
          console.log(
            `Bot joined for ${username}`
          );

          bot.status =
            "joined";
        }
      );

      client.on(
        "spawn",
        () => {
          console.log(
            `Bot spawned for ${username}`
          );

          bot.connected = true;
          bot.spawned = true;
          bot.status =
            "online";

          const session =
            microsoftSessions.get(
              sessionId
            );

          if (session) {
            session.status =
              "connected";

            session.botStatus =
              "online";
          }
        }
      );

      client.on(
        "text",
        packet => {
          console.log(
            `[${username}]`,
            packet
          );
        }
      );

      client.on(
        "error",
        error => {
          console.error(
            `Bot error for ${username}:`,
            error
          );

          bot.status =
            "error";
        }
      );

      client.on(
        "close",
        () => {
          console.log(
            `Bot closed for ${username}`
          );

          bot.connected = false;
          bot.spawned = false;
          bot.status =
            "offline";

          const session =
            microsoftSessions.get(
              sessionId
            );

          if (session) {
            session.status =
              "disconnected";

            session.botStatus =
              "offline";
          }
        }
      );

      res.json({
        success: true,
        sessionId,
        message:
          "Microsoft login started."
      });
    } catch (error) {
      console.error(
        "MICROSOFT LOGIN ERROR:",
        error
      );

      const session =
        microsoftSessions.get(
          sessionId
        );

      if (session) {
        session.status =
          "error";

        session.message =
          error.message;
      }

      res.status(500).json({
        error:
          error.message ||
          "Microsoft login failed.",
        sessionId
      });
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
        error: "Not logged in."
      });
    }

    const session =
      microsoftSessions.get(
        req.params.sessionId
      );

    if (!session) {
      return res.status(404).json({
        error:
          "Microsoft session not found."
      });
    }

    if (
      session.username !==
      username
    ) {
      return res.status(403).json({
        error: "Unauthorized."
      });
    }

    res.json({
      success: true,
      ...session
    });
  }
);

/* =========================================================
   DISCORD
   ========================================================= */

const discordClient =
  new Client({
    intents: [
      GatewayIntentBits.Guilds
    ]
  });

const monthlyCommand =
  new SlashCommandBuilder()
    .setName("genkeymonthly")
    .setDescription(
      "Generate a 30-day Hqbot activation key"
    );

const lifetimeCommand =
  new SlashCommandBuilder()
    .setName("genkeylifetime")
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
          version: "10"
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
        "Discord slash commands registered."
      );
    } catch (error) {
      console.error(
        "Discord command registration error:",
        error
      );
    }
  }
);

/* =========================================================
   DISCORD COMMANDS
   ========================================================= */

discordClient.on(
  "interactionCreate",
  async interaction => {
    if (!interaction.isChatInputCommand()) {
      return;
    }

    /*
      Optional Discord admin protection.

      If DISCORD_ADMIN_USER_ID is set,
      only that Discord account can generate keys.
    */

    if (
      interaction.commandName ===
        "genkeymonthly" ||
      interaction.commandName ===
        "genkeylifetime"
    ) {
      const adminDiscordId =
        process.env.DISCORD_ADMIN_USER_ID;

      if (
        adminDiscordId &&
        interaction.user.id !==
          adminDiscordId
      ) {
        return interaction.reply({
          content:
            "❌ You are not authorized to generate Hqbot keys.",
          ephemeral: true
        });
      }
    }

    if (
      interaction.commandName ===
      "genkeymonthly"
    ) {
      const key =
        generateActivationKey();

      activationKeys.set(
        key,
        {
          type: "monthly",
          createdAt: Date.now()
        }
      );

      const saved =
        saveActivationKeys();

      if (!saved) {
        activationKeys.delete(key);

        return interaction.reply({
          content:
            "❌ Failed to save the activation key.",
          ephemeral: true
        });
      }

      return interaction.reply({
        content:
          `🔐 **Hqbot Monthly Key**\n\n` +
          `\`${key}\`\n\n` +
          `⏳ 30 days start when the key is used.`,
        ephemeral: true
      });
    }

    if (
      interaction.commandName ===
      "genkeylifetime"
    ) {
      const key =
        generateActivationKey();

      activationKeys.set(
        key,
        {
          type: "lifetime",
          createdAt: Date.now()
        }
      );

      const saved =
        saveActivationKeys();

      if (!saved) {
        activationKeys.delete(key);

        return interaction.reply({
          content:
            "❌ Failed to save the activation key.",
          ephemeral: true
        });
      }

      return interaction.reply({
        content:
          `♾️ **Hqbot Lifetime Key**\n\n` +
          `\`${key}\`\n\n` +
          `♾️ Never expires.`,
        ephemeral: true
      });
    }
  }
);

/* =========================================================
   START DISCORD
   ========================================================= */

if (
  process.env.DISCORD_BOT_TOKEN
) {
  discordClient
    .login(
      process.env.DISCORD_BOT_TOKEN
    )
    .catch(error => {
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
  "0.0.0.0",
  () => {
    console.log(
      `Hqbot backend running on port ${PORT}`
    );

    console.log(
      `Data directory: ${DATA_DIR}`
    );

    console.log(
      `Users loaded: ${users.size}`
    );

    console.log(
      `Activation keys loaded: ${activationKeys.size}`
    );
  }
);
