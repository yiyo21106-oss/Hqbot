const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Authflow } = require("prismarine-auth");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

const loginSessions = new Map();

app.get("/", (req, res) => {
  res.json({
    name: "Hqbot",
    status: "online"
  });
});

app.post("/api/microsoft/login", async (req, res) => {
  const sessionId = crypto.randomUUID();

  loginSessions.set(sessionId, {
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
        const session = loginSessions.get(sessionId);

        if (!session) return;

        session.code = data.user_code;
        session.verificationUri = data.verification_uri;
        session.message = data.message;
        session.status = "waiting_for_login";

        console.log("Microsoft device code:", data.user_code);
        console.log("Login:", data.verification_uri);
      }
    );

    await auth.getXboxToken();

    const session = loginSessions.get(sessionId);

    if (session) {
      session.status = "connected";
    }
  } catch (error) {
    console.error("Microsoft login error:", error);

    const session = loginSessions.get(sessionId);

    if (session) {
      session.status = "error";
      session.error = error.message;
    }
  }
});

app.get("/api/microsoft/login/:sessionId", (req, res) => {
  const session = loginSessions.get(req.params.sessionId);

  if (!session) {
    return res.status(404).json({
      error: "Login session not found"
    });
  }

  res.json(session);
});

app.listen(PORT, () => {
  console.log(`Hqbot backend running on port ${PORT}`);
});
