const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const {
  Authflow,
  Titles
} = require("prismarine-auth");

const bedrock = require("bedrock-protocol");

const {
  Client,
  GatewayIntentBits,
  REST,
  Routes,
  SlashCommandBuilder
} = require("discord.js");

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.use(cors());
app.use(express.json());

/* =========================================================
   DATA STORAGE
   ========================================================= */

const DATA_DIR =
  process.env.DATA_DIR || "/data";

try {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, {
      recursive: true
    });
  }
} catch (error) {
  console.error(
    "Could not create DATA_DIR:",
    error
  );
}

const USERS_FILE =
  path.join(DATA_DIR, "users.json");

const SESSIONS_FILE =
  path.join(DATA_DIR, "sessions.json");

const KEYS_FILE =
  path.join(DATA_DIR, "keys.json");

const MICROSOFT_ACCOUNTS_FILE =
  path.join(
    DATA_DIR,
    "microsoft-accounts.json"
  );

const SNIPE_AUTH_FILE =
  path.join(DATA_DIR, "snipe-auth.json");

const AUTH_CACHE_DIR =
  path.join(DATA_DIR, "auth-cache");

try {
  if (!fs.existsSync(AUTH_CACHE_DIR)) {
    fs.mkdirSync(AUTH_CACHE_DIR, {
      recursive: true
    });
  }
} catch (error) {
  console.error(
    "Could not create auth cache:",
    error
  );
}

/* =========================================================
   JSON
   ========================================================= */

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

    const raw = fs.readFileSync(
      file,
      "utf8"
    );

    if (!raw.trim()) {
      return fallback;
    }

    return JSON.parse(raw);
  } catch (error) {
    console.error(
      "JSON load error:",
      file,
      error
    );

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

    fs.renameSync(
      tempFile,
      file
    );

    return true;
  } catch (error) {
    console.error(
      "JSON save error:",
      file,
      error
    );

    return false;
  }
}

/* =========================================================
   DATA
   ========================================================= */

const users =
  new Map(
    Object.entries(
      loadJSON(USERS_FILE, {})
    )
  );

const loginSessions =
  new Map(
    Object.entries(
      loadJSON(SESSIONS_FILE, {})
    )
  );

const activationKeys =
  new Map(
    Object.entries(
      loadJSON(KEYS_FILE, {})
    )
  );

const microsoftAccounts =
  new Map(
    Object.entries(
      loadJSON(
        MICROSOFT_ACCOUNTS_FILE,
        {}
      )
    )
  );

const microsoftSessions =
  new Map();

const microsoftAuthflows =
  new Map();

const activeBots =
  new Map();

/* =========================================================
   SNIPE
   ========================================================= */

let snipeAuthInfo =
  loadJSON(
    SNIPE_AUTH_FILE,
    null
  );

let snipeRunning = false;

const SNIPE_COOLDOWN =
  30 * 1000;

const snipeCooldowns =
  new Map();

const SNIPE_MAX_CHECKS =
  40;

/* =========================================================
   PASSWORDS
   ========================================================= */

function hashPassword(password) {
  const salt =
    crypto
      .randomBytes(16)
      .toString("hex");

  const hash =
    crypto
      .scryptSync(
        password,
        salt,
        64
      )
      .toString("hex");

  return `${salt}:${hash}`;
}

function verifyPassword(
  password,
  storedPassword
) {
  try {
    if (
      !storedPassword ||
      !storedPassword.includes(":")
    ) {
      return false;
    }

    const [
      salt,
      storedHash
    ] =
      storedPassword.split(":");

    const hash =
      crypto
        .scryptSync(
          password,
          salt,
          64
        )
        .toString("hex");

    const a =
      Buffer.from(
        hash,
        "hex"
      );

    const b =
      Buffer.from(
        storedHash,
        "hex"
      );

    if (a.length !== b.length) {
      return false;
    }

    return crypto.timingSafeEqual(
      a,
      b
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
  return String(value || "")
    .trim();
}

/* =========================================================
   LOGIN SESSIONS
   ========================================================= */

function saveSessions() {
  return saveJSON(
    SESSIONS_FILE,
    Object.fromEntries(
      loginSessions
    )
  );
}

function createLoginToken(username) {
  const token =
    crypto
      .randomBytes(48)
      .toString("hex");

  loginSessions.set(
    token,
    {
      username,
      createdAt: Date.now()
    }
  );

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

  const token =
    header.slice(7);

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

  const token =
    header.slice(7);

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
   PLANS
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
      error:
        "You must login first."
    });

    return null;
  }

  const user =
    users.get(username);

  if (!user) {
    res.status(401).json({
      error:
        "Account not found."
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
    try {
      const username =
        normalizeUsername(
          req.body.username
        );

      const password =
        String(
          req.body.password || ""
        );

      const activationKey =
        normalizeActivationKey(
          req.body.activationKey
        );

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

      if (username.length < 3) {
        return res.status(400).json({
          error:
            "Username must be at least 3 characters."
        });
      }

      if (password.length < 4) {
        return res.status(400).json({
          error:
            "Password must be at least 4 characters."
        });
      }

      if (users.has(username)) {
        return res.status(400).json({
          error:
            "Username already exists."
        });
      }

      const keyData =
        activationKeys.get(
          activationKey
        );

      if (!keyData) {
        return res.status(400).json({
          error:
            "Invalid activation key."
        });
      }

      const plan =
        keyData.type;

      if (
        plan !== "monthly" &&
        plan !== "lifetime"
      ) {
        return res.status(400).json({
          error:
            "Invalid activation key type."
        });
      }

      const now =
        Date.now();

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

      const saved =
        saveJSON(
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

      activationKeys.delete(
        activationKey
      );

      saveJSON(
        KEYS_FILE,
        Object.fromEntries(
          activationKeys
        )
      );

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
    } catch (error) {
      console.error(
        "REGISTER ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Registration failed."
      });
    }
  }
);

/* =========================================================
   LOGIN
   ========================================================= */

app.post(
  "/api/auth/login",
  (req, res) => {
    try {
      const username =
        normalizeUsername(
          req.body.username
        );

      const password =
        String(
          req.body.password || ""
        );

      if (
        !username ||
        !password
      ) {
        return res.status(400).json({
          error:
            "Username and password are required."
        });
      }

      const user =
        users.get(username);

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

      const token =
        createLoginToken(username);

      console.log(
        `LOGIN SUCCESS: ${username}`
      );

      res.json({
        success: true,
        message:
          "Login successful.",
        token,
        username,
        plan: user.plan,
        expiresAt:
          user.expiresAt
      });
    } catch (error) {
      console.error(
        "LOGIN ERROR:",
        error
      );

      res.status(500).json({
        error:
          "Login failed."
      });
    }
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
      plan: user.plan,
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
      error:
        "Unauthorized."
    });

    return false;
  }

  return true;
}

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
    Object.fromEntries(
      activationKeys
    )
  );
}

app.post(
  "/api/admin/generate-key",
  (req, res) => {
    if (!checkAdmin(req, res)) {
      return;
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

    activationKeys.set(
      key,
      {
        type,
        createdAt:
          Date.now()
      }
    );

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
      active:
        keys.length > 0,
      total:
        keys.length,
      keys
    });
  }
);

/* =========================================================
   BOT
   ========================================================= */

function getBotForUser(username) {
  return activeBots.get(username);
}

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
        !!bot.connected &&
        !!bot.spawned,
      status:
        bot.status ||
        "offline",
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
      requireActivePlan(
        req,
        res
      );

    if (!user) {
      return;
    }

    const command =
      String(
        req.body.command || ""
      ).trim();

    if (!command) {
      return res.status(400).json({
        error:
          "Command is required."
      });
    }

    const bot =
      getBotForUser(
        user.username
      );

    if (
      !bot ||
      !bot.client ||
      !bot.connected ||
      !bot.spawned
    ) {
      return res.status(400).json({
        error:
          "Bot is not connected."
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
          needs_translation:
            false,
          source_name:
            bot.client.username ||
            "",
          xuid: "",
          platform_chat_id:
            "",
          message:
            finalCommand
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
   INVENTORY
   ========================================================= */

function isNonEmptyItem(item) {
  if (!item) {
    return false;
  }

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
  if (!item) {
    return 0;
  }

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
  if (!item) {
    return null;
  }

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
      item.name ?? null,
    count:
      getItemCount(item),
    stackId:
      getItemStackId(item)
  };
}

function attachInventoryListeners(
  username,
  bot
) {
  if (!bot.client) {
    return;
  }

  bot.inventory =
    Array(36).fill(null);

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

app.get(
  "/api/bot/inventory",
  (req, res) => {
    const user =
      requireActivePlan(
        req,
        res
      );

    if (!user) {
      return;
    }

    const bot =
      getBotForUser(
        user.username
      );

    if (
      !bot ||
      !bot.connected ||
      !bot.spawned
    ) {
      return res.status(400).json({
        error:
          "Bot is not connected."
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

app.post(
  "/api/bot/inventory/drop",
  async (req, res) => {
    const user =
      requireActivePlan(
        req,
        res
      );

    if (!user) {
      return;
    }

    const bot =
      getBotForUser(
        user.username
      );

    if (
      !bot ||
      !bot.connected ||
      !bot.spawned ||
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
        error:
          "Invalid slot."
      });
    }

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
   MICROSOFT AUTH
   ========================================================= */

/*
  Stable ID:
  One Hqbot user = one Authflow cache.

  The ID no longer changes every time
  the user presses Add Account.
*/

function getMicrosoftAuthId(username) {
  return (
    "hqbot-account-" +
    username
  );
}

function saveMicrosoftAccounts() {
  return saveJSON(
    MICROSOFT_ACCOUNTS_FILE,
    Object.fromEntries(
      microsoftAccounts
    )
  );
}

function getMicrosoftAccount(username) {
  return (
    microsoftAccounts.get(
      username
    ) || null
  );
}

function setMicrosoftAccount(
  username,
  patch
) {
  const existing =
    microsoftAccounts.get(
      username
    ) || {
      username
    };

  const updated = {
    ...existing,
    ...patch,
    username,
    updatedAt:
      Date.now()
  };

  microsoftAccounts.set(
    username,
    updated
  );

  saveMicrosoftAccounts();

  return updated;
}

function updateMicrosoftSession(
  sessionId,
  patch
) {
  const session =
    microsoftSessions.get(
      sessionId
    );

  if (!session) {
    return null;
  }

  Object.assign(
    session,
    patch
  );

  microsoftSessions.set(
    sessionId,
    session
  );

  return session;
}

function parseMicrosoftDeviceCode(
  message
) {
  const text =
    String(message || "");

  let user_code = null;
  let verification_uri = null;

  const urlMatch =
    text.match(
      /https?:\/\/[^\s]+/i
    );

  if (urlMatch) {
    verification_uri =
      urlMatch[0].replace(
        /[),.]+$/,
        ""
      );
  }

  const patterns = [
    /(?:code|code is|enter(?: the)? code)[\s:]+([A-Z0-9-]{4,})/i,
    /\b([A-Z0-9]{4,8}-[A-Z0-9]{3,8})\b/
  ];

  for (const regex of patterns) {
    const match =
      text.match(regex);

    if (match) {
      user_code =
        match[1];

      break;
    }
  }

  return {
    user_code,
    verification_uri
  };
}

/* =========================================================
   AUTHFLOW OPTIONS
   ========================================================= */

/*
  prismarine-auth currently exposes
  MinecraftNintendoSwitch as its known
  Bedrock client ID.

  Win32 makes the authentication device
  a Windows/PC-type device.

  This does NOT mean Hqbot only works
  for Nintendo or only for PC users.
  Hqbot itself can be opened from
  PC/mobile/browser.
*/

function getAuthflowOptions() {
  return {
    flow: "live",
    authTitle:
      Titles.MinecraftNintendoSwitch,
    deviceType:
      process.env.HQBOT_AUTH_DEVICE_TYPE ||
      "Win32",
    forceRefresh: false
  };
}

/* =========================================================
   SAVE SNIPE AUTH
   ========================================================= */

function saveSnipeAuthInfo(
  username,
  authId
) {
  snipeAuthInfo = {
    username,
    authId,
    savedAt:
      Date.now()
  };

  saveJSON(
    SNIPE_AUTH_FILE,
    snipeAuthInfo
  );
}

/* =========================================================
   CREATE AUTHFLOW
   ========================================================= */

function createMicrosoftAuthflow(
  username,
  sessionId
) {
  const authId =
    getMicrosoftAuthId(
      username
    );

  const auth =
    new Authflow(
      authId,
      AUTH_CACHE_DIR,
      getAuthflowOptions(),
      deviceCode => {
        try {
          const patch = {};

          if (
            deviceCode &&
            typeof deviceCode ===
              "object"
          ) {
            patch.user_code =
              deviceCode.user_code ||
              null;

            patch.verification_uri =
              deviceCode.verification_uri ||
              deviceCode.verification_uri_complete ||
              null;

            patch.message =
              deviceCode.message ||
              "Enter the displayed code on Microsoft's website.";

            if (
              deviceCode.expires_in
            ) {
              patch.expiresAt =
                Date.now() +
                Number(
                  deviceCode.expires_in
                ) *
                  1000;
            }
          } else {
            const text =
              String(
                deviceCode || ""
              );

            const parsed =
              parseMicrosoftDeviceCode(
                text
              );

            patch.message =
              text;

            if (
              parsed.user_code
            ) {
              patch.user_code =
                parsed.user_code;
            }

            if (
              parsed.verification_uri
            ) {
              patch.verification_uri =
                parsed.verification_uri;
            }
          }

          patch.status =
            "waiting_for_login";

          updateMicrosoftSession(
            sessionId,
            patch
          );

          console.log(
            `[${username}] Microsoft device code:`,
            patch.user_code
          );

          console.log(
            `[${username}] Microsoft URL:`,
            patch.verification_uri
          );
        } catch (error) {
          console.error(
            "Microsoft device callback error:",
            error
          );
        }
      }
    );

  microsoftAuthflows.set(
    username,
    auth
  );

  return {
    auth,
    authId
  };
}

/* =========================================================
   START MICROSOFT AUTH
   ========================================================= */

async function startMicrosoftAuth(
  sessionId,
  username
) {
  try {
    updateMicrosoftSession(
      sessionId,
      {
        status: "starting",
        botStatus: "offline",
        message:
          "Starting Microsoft sign-in..."
      }
    );

    let auth =
      microsoftAuthflows.get(
        username
      );

    let authId =
      getMicrosoftAuthId(
        username
      );

    if (!auth) {
      const created =
        createMicrosoftAuthflow(
          username,
          sessionId
        );

      auth =
        created.auth;

      authId =
        created.authId;
    }

    setMicrosoftAccount(
      username,
      {
        authId,
        connected: false,
        status:
          "authenticating"
      }
    );

    saveSnipeAuthInfo(
      username,
      authId
    );

    updateMicrosoftSession(
      sessionId,
      {
        status:
          "waiting_for_login",
        message:
          "Waiting for Microsoft sign-in..."
      }
    );

    /*
      Xbox authentication.
      Cached credentials will be reused
      when available.
    */

    const xboxToken =
      await auth.getXboxToken();

    if (
      !xboxToken ||
      !xboxToken.userHash ||
      !xboxToken.XSTSToken
    ) {
      throw new Error(
        "Microsoft sign-in finished, but Xbox authentication token was not returned."
      );
    }

    /*
      Microsoft/Xbox is now authenticated.
      This is NOT yet the same as the
      Minecraft bot being online.
    */

    setMicrosoftAccount(
      username,
      {
        authId,
        connected: true,
        status: "connected",
        connectedAt:
          Date.now(),
        xuid:
          xboxToken.userXUID ||
          null,
        userHash:
          xboxToken.userHash ||
          null
      }
    );

    updateMicrosoftSession(
      sessionId,
      {
        status:
          "authenticated",
        microsoftConnected:
          true,
        botStatus:
          "offline",
        message:
          "Microsoft/Xbox account connected successfully."
      }
    );

    console.log(
      `[${username}] Microsoft/Xbox authentication SUCCESS.`
    );

    /* =====================================================
       MINECRAFT SERVER
       ===================================================== */

    const host =
      process.env.LBSG_HOST;

    const port =
      Number(
        process.env.LBSG_PORT ||
          19132
      );

    if (!host) {
      console.log(
        `[${username}] LBSG_HOST is not configured.`
      );

      updateMicrosoftSession(
        sessionId,
        {
          status:
            "authenticated",
          microsoftConnected:
            true,
          botStatus:
            "offline",
          message:
            "Microsoft/Xbox account connected. Minecraft server is not configured."
        }
      );

      return;
    }

    /* =====================================================
       REMOVE OLD BOT
       ===================================================== */

    const oldBot =
      activeBots.get(
        username
      );

    if (
      oldBot &&
      oldBot.client
    ) {
      try {
        oldBot.client.disconnect();
      } catch {}

      activeBots.delete(
        username
      );
    }

    updateMicrosoftSession(
      sessionId,
      {
        status:
          "authenticated",
        microsoftConnected:
          true,
        botStatus:
          "connecting",
        message:
          "Microsoft/Xbox connected. Connecting Minecraft bot..."
      }
    );

    /* =====================================================
       BEDROCK CLIENT
       ===================================================== */

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

    /* =====================================================
       CONNECT
       ===================================================== */

    client.on(
      "connect",
      () => {
        console.log(
          `Bot connected for ${username}`
        );

        bot.connected = true;
        bot.status = "connected";

        updateMicrosoftSession(
          sessionId,
          {
            status:
              "authenticated",
            microsoftConnected:
              true,
            botStatus:
              "connecting",
            message:
              "Microsoft/Xbox connected. Minecraft bot joining server..."
          }
        );
      }
    );

    /* =====================================================
       JOIN
       ===================================================== */

    client.on(
      "join",
      () => {
        console.log(
          `Bot joined for ${username}`
        );

        bot.status = "joined";
      }
    );

    /* =====================================================
       SPAWN = ACTUALLY ONLINE
       ===================================================== */

    client.on(
      "spawn",
      () => {
        console.log(
          `Bot spawned for ${username}`
        );

        bot.connected = true;
        bot.spawned = true;
        bot.status = "online";

        updateMicrosoftSession(
          sessionId,
          {
            status:
              "connected",
            microsoftConnected:
              true,
            botStatus:
              "online",
            message:
              "Microsoft/Xbox account connected successfully. Bot is online."
          }
        );
      }
    );

    /* =====================================================
       TEXT
       ===================================================== */

    client.on(
      "text",
      packet => {
        console.log(
          `[${username}]`,
          packet
        );
      }
    );

    /* =====================================================
       ERROR
       ===================================================== */

    client.on(
      "error",
      error => {
        console.error(
          `Bot error for ${username}:`,
          error
        );

        bot.connected = false;
        bot.spawned = false;
        bot.status = "error";

        updateMicrosoftSession(
          sessionId,
          {
            status:
              "authenticated",
            microsoftConnected:
              true,
            botStatus:
              "offline",
            message:
              "Microsoft/Xbox account is connected, but the Minecraft bot could not connect."
          }
        );
      }
    );

    /* =====================================================
       CLOSE
       ===================================================== */

    client.on(
      "close",
      () => {
        console.log(
          `Bot closed for ${username}`
        );

        bot.connected = false;
        bot.spawned = false;
        bot.status = "offline";

        updateMicrosoftSession(
          sessionId,
          {
            status:
              "authenticated",
            microsoftConnected:
              true,
            botStatus:
              "offline",
            message:
              "Microsoft/Xbox account is still connected. Minecraft bot is offline."
          }
        );
      }
    );
  } catch (error) {
    console.error(
      `MICROSOFT AUTH ERROR for ${username}:`,
      error
    );

    const current =
      getMicrosoftAccount(
        username
      );

    const microsoftWasConnected =
      !!(
        current &&
        current.connected
      );

    updateMicrosoftSession(
      sessionId,
      {
        status:
          microsoftWasConnected
            ? "authenticated"
            : "error",
        microsoftConnected:
          microsoftWasConnected,
        botStatus:
          "offline",
        message:
          error.message ||
          "Microsoft sign-in failed."
      }
    );

    if (!microsoftWasConnected) {
      setMicrosoftAccount(
        username,
        {
          authId:
            getMicrosoftAuthId(
              username
            ),
          connected: false,
          status: "error"
        }
      );
    }
  }
}

/* =========================================================
   MICROSOFT LOGIN
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

    const username =
      user.username;

    /*
      If an old login attempt exists,
      replace it with a fresh session.
    */

    const sessionId =
      crypto.randomUUID();

    microsoftSessions.set(
      sessionId,
      {
        username,
        status: "starting",
        microsoftConnected:
          false,
        botStatus: "offline",
        createdAt:
          Date.now(),
        expiresAt: null,
        message:
          "Starting Microsoft sign-in...",
        user_code: null,
        verification_uri: null
      }
    );

    startMicrosoftAuth(
      sessionId,
      username
    ).catch(error => {
      console.error(
        "Background Microsoft auth error:",
        error
      );

      updateMicrosoftSession(
        sessionId,
        {
          status: "error",
          microsoftConnected:
            false,
          botStatus:
            "offline",
          message:
            error.message ||
            "Microsoft login failed."
        }
      );
    });

    res.json({
      success: true,
      sessionId,
      message:
        "Microsoft login started."
    });
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
          "Microsoft session not found."
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

    const account =
      getMicrosoftAccount(
        username
      );

    res.json({
      success: true,
      ...session,
      microsoftConnected:
        !!(
          account &&
          account.connected
        )
    });
  }
);

/* =========================================================
   MICROSOFT ACCOUNT STATUS
   ========================================================= */

app.get(
  "/api/microsoft/account",
  (req, res) => {
    const user =
      requireActivePlan(
        req,
        res
      );

    if (!user) {
      return;
    }

    const account =
      getMicrosoftAccount(
        user.username
      );

    if (!account) {
      return res.json({
        connected: false,
        status:
          "not_connected",
        username:
          user.username,
        botOnline: false
      });
    }

    let auth =
      microsoftAuthflows.get(
        user.username
      );

    if (!auth) {
      try {
        auth =
          new Authflow(
            account.authId ||
              getMicrosoftAuthId(
                user.username
              ),
            AUTH_CACHE_DIR,
            getAuthflowOptions()
          );

        microsoftAuthflows.set(
          user.username,
          auth
        );
      } catch (error) {
        console.error(
          "Could not restore Microsoft Authflow:",
          error
        );
      }
    }

    const bot =
      getBotForUser(
        user.username
      );

    res.json({
      connected:
        !!account.connected,
      status:
        account.connected
          ? "connected"
          : "not_connected",
      username:
        user.username,
      connectedAt:
        account.connectedAt ||
        null,
      botOnline:
        !!(
          bot &&
          bot.connected &&
          bot.spawned
        ),
      botStatus:
        bot?.status ||
        "offline"
    });
  }
);

/* =========================================================
   SNIPE HELPERS
   ========================================================= */

const SNIPE_CHARACTERS =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

function generateFourCharacterGamertag() {
  let result = "";

  for (
    let i = 0;
    i < 4;
    i++
  ) {
    result +=
      SNIPE_CHARACTERS[
        crypto.randomInt(
          0,
          SNIPE_CHARACTERS.length
        )
      ];
  }

  return result;
}

async function getSnipeAuthflow() {
  /*
    First use saved account.
  */

  if (
    snipeAuthInfo &&
    snipeAuthInfo.username
  ) {
    const username =
      snipeAuthInfo.username;

    let auth =
      microsoftAuthflows.get(
        username
      );

    if (auth) {
      return auth;
    }

    const account =
      getMicrosoftAccount(
        username
      );

    if (
      account &&
      account.connected
    ) {
      try {
        auth =
          new Authflow(
            account.authId ||
              getMicrosoftAuthId(
                username
              ),
            AUTH_CACHE_DIR,
            getAuthflowOptions()
          );

        microsoftAuthflows.set(
          username,
          auth
        );

        return auth;
      } catch (error) {
        console.error(
          "Could not restore snipe Authflow:",
          error
        );
      }
    }
  }

  /*
    Otherwise use any connected account.
  */

  for (
    const [
      username,
      account
    ] of microsoftAccounts
  ) {
    if (
      account &&
      account.connected
    ) {
      let auth =
        microsoftAuthflows.get(
          username
        );

      if (!auth) {
        try {
          auth =
            new Authflow(
              account.authId ||
                getMicrosoftAuthId(
                  username
                ),
              AUTH_CACHE_DIR,
              getAuthflowOptions()
            );

          microsoftAuthflows.set(
            username,
            auth
          );
        } catch {
          continue;
        }
      }

      saveSnipeAuthInfo(
        username,
        account.authId ||
          getMicrosoftAuthId(
            username
          )
      );

      return auth;
    }
  }

  return null;
}

async function checkXboxGamertag(
  auth,
  gamertag
) {
  const xboxToken =
    await auth.getXboxToken();

  if (
    !xboxToken ||
    !xboxToken.userHash ||
    !xboxToken.XSTSToken
  ) {
    throw new Error(
      "Could not obtain Xbox authentication token."
    );
  }

  const encoded =
    encodeURIComponent(
      gamertag
    );

  const url =
    `https://profile.xboxlive.com/users/gt(${encoded})/profile/settings?settings=Gamertag`;

  const response =
    await fetch(
      url,
      {
        method: "GET",
        headers: {
          Authorization:
            `XBL3.0 x=${xboxToken.userHash};${xboxToken.XSTSToken}`,
          "x-xbl-contract-version":
            "2",
          Accept:
            "application/json"
        }
      }
    );

  if (response.status === 404) {
    return "available";
  }

  if (response.status === 200) {
    return "taken";
  }

  if (
    response.status === 401 ||
    response.status === 403
  ) {
    throw new Error(
      `Xbox authentication rejected the request (${response.status}).`
    );
  }

  if (response.status === 429) {
    throw new Error(
      "Xbox rate limit reached. Try /snipe again later."
    );
  }

  return "unknown";
}

function sleep(ms) {
  return new Promise(
    resolve =>
      setTimeout(resolve, ms)
  );
}

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

const snipeCommand =
  new SlashCommandBuilder()
    .setName("snipe")
    .setDescription(
      "Find an exact 4-character Xbox gamertag"
    );

/* =========================================================
   DISCORD READY
   ========================================================= */

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

      const commands = [
        monthlyCommand.toJSON(),
        lifetimeCommand.toJSON(),
        snipeCommand.toJSON()
      ];

      /*
        If DISCORD_GUILD_ID is provided,
        commands appear almost immediately
        in that server.

        Otherwise they are registered globally.
      */

      if (
        process.env.DISCORD_GUILD_ID
      ) {
        await rest.put(
          Routes.applicationGuildCommands(
            discordClient.user.id,
            process.env.DISCORD_GUILD_ID
          ),
          {
            body: commands
          }
        );

        console.log(
          "Discord guild slash commands registered."
        );
      } else {
        await rest.put(
          Routes.applicationCommands(
            discordClient.user.id
          ),
          {
            body: commands
          }
        );

        console.log(
          "Discord global slash commands registered."
        );
      }
    } catch (error) {
      console.error(
        "Discord command registration error:",
        error
      );
    }
  }
);

/* =========================================================
   DISCORD INTERACTIONS
   ========================================================= */

discordClient.on(
  "interactionCreate",
  async interaction => {
    if (
      !interaction.isChatInputCommand()
    ) {
      return;
    }

    try {
      /*
        IMPORTANT FIX:

        A Discord interaction has only a few
        seconds to be acknowledged.

        We acknowledge EVERY command immediately.
        This prevents:
        "The application did not respond."
      */

      await interaction.deferReply({
        ephemeral: true
      });

      /* =====================================================
         AUTHORIZATION
         ===================================================== */

      const adminDiscordId =
        process.env
          .DISCORD_ADMIN_USER_ID;

      if (
        adminDiscordId &&
        interaction.user.id !==
          adminDiscordId
      ) {
        return interaction.editReply({
          content:
            "❌ You are not authorized to use this command."
        });
      }

      /* =====================================================
         MONTHLY KEY
         ===================================================== */

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
            createdAt:
              Date.now()
          }
        );

        const saved =
          saveActivationKeys();

        if (!saved) {
          activationKeys.delete(
            key
          );

          return interaction.editReply({
            content:
              "❌ Failed to save the activation key."
          });
        }

        return interaction.editReply({
          content:
            `🔐 **Hqbot Monthly Key**\n\n` +
            `\`${key}\`\n\n` +
            `⏳ 30 days start when the key is used.`
        });
      }

      /* =====================================================
         LIFETIME KEY
         ===================================================== */

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
            createdAt:
              Date.now()
          }
        );

        const saved =
          saveActivationKeys();

        if (!saved) {
          activationKeys.delete(
            key
          );

          return interaction.editReply({
            content:
              "❌ Failed to save the activation key."
          });
        }

        return interaction.editReply({
          content:
            `♾️ **Hqbot Lifetime Key**\n\n` +
            `\`${key}\`\n\n` +
            `♾️ Never expires.`
        });
      }

      /* =====================================================
         SNIPE
         ===================================================== */

      if (
        interaction.commandName ===
        "snipe"
      ) {
        if (snipeRunning) {
          return interaction.editReply({
            content:
              "⏳ A /snipe search is already running."
          });
        }

        const lastSnipe =
          snipeCooldowns.get(
            interaction.user.id
          );

        if (
          lastSnipe &&
          Date.now() -
            lastSnipe <
            SNIPE_COOLDOWN
        ) {
          const seconds =
            Math.ceil(
              (
                SNIPE_COOLDOWN -
                (
                  Date.now() -
                  lastSnipe
                )
              ) /
                1000
            );

          return interaction.editReply({
            content:
              `⏳ Try /snipe again in ${seconds}s.`
          });
        }

        snipeCooldowns.set(
          interaction.user.id,
          Date.now()
        );

        snipeRunning = true;

        await interaction.editReply({
          content:
            "🔎 **Snipe started.**\nChecking exact 4-character Xbox gamertags..."
        });

        try {
          const auth =
            await getSnipeAuthflow();

          if (!auth) {
            snipeRunning = false;

            return interaction.editReply({
              content:
                "❌ I don't have a connected Microsoft/Xbox account yet.\n\nUse **Hqbot → Add Microsoft Account**, finish the Microsoft login, then try `/snipe` again."
            });
          }

          const checked =
            new Set();

          let found = null;
          let checks = 0;

          for (
            let attempt = 0;
            attempt <
            SNIPE_MAX_CHECKS;
            attempt++
          ) {
            let gamertag;

            do {
              gamertag =
                generateFourCharacterGamertag();
            } while (
              checked.has(gamertag)
            );

            checked.add(
              gamertag
            );

            checks++;

            console.log(
              `[SNIPE] Checking ${gamertag}`
            );

            const result =
              await checkXboxGamertag(
                auth,
                gamertag
              );

            if (
              result ===
              "available"
            ) {
              found =
                gamertag;

              break;
            }

            await sleep(650);
          }

          snipeRunning = false;

          if (!found) {
            return interaction.editReply({
              content:
                `❌ I couldn't confirm an unused 4-character gamertag after ${checks} checks.\n\nTry **/snipe** again later.`
            });
          }

          return interaction.editReply({
            content:
              `🎯 **4C GAMERTAG FOUND**\n\n` +
              `# \`${found}\`\n\n` +
              `Length: **4 characters**\n` +
              `Characters: **letters + numbers only**\n` +
              `Checks: **${checks}**\n\n` +
              `⚠️ Xbox lookup found no profile for this exact name at the time of checking.`
          });
        } catch (error) {
          snipeRunning = false;

          console.error(
            "SNIPE ERROR:",
            error
          );

          return interaction.editReply({
            content:
              `❌ **Snipe error**\n\n${error.message || "Could not check Xbox gamertags."}`
          });
        }
      }

      /*
        Unknown command.
      */

      return interaction.editReply({
        content:
          "❌ Unknown command."
      });
    } catch (error) {
      console.error(
        "DISCORD INTERACTION ERROR:",
        error
      );

      try {
        if (
          interaction.deferred ||
          interaction.replied
        ) {
          await interaction.editReply({
            content:
              "❌ Something went wrong while processing the command."
          });
        } else {
          await interaction.reply({
            content:
              "❌ Something went wrong while processing the command.",
            ephemeral: true
          });
        }
      } catch (replyError) {
        console.error(
          "DISCORD REPLY ERROR:",
          replyError
        );
      }
    }
  }
);

/* =========================================================
   DISCORD LOGIN
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

    console.log(
      `Microsoft accounts loaded: ${microsoftAccounts.size}`
    );

    console.log(
      "Persistent Microsoft/Xbox authentication enabled."
    );

    console.log(
      "Discord interaction timeout protection enabled."
    );

    console.log(
      "4-character /snipe enabled."
    );
  }
);
