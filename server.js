"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const path = require("node:path");
const express = require("express");
const Database = require("better-sqlite3");

const app = express();
const port = Number(process.env.PORT || 3000);
const sessionDuration = 30 * 24 * 60 * 60 * 1000;
const dataDirectory = path.resolve(process.env.FARM_DATA_DIR || path.join(__dirname, "data"));

fs.mkdirSync(dataDirectory, { recursive: true });

const database = new Database(path.join(dataDirectory, "farm.sqlite"));
database.pragma("journal_mode = WAL");
database.pragma("foreign_keys = ON");
database.exec(`
    CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL COLLATE NOCASE UNIQUE,
        password_hash TEXT NOT NULL,
        password_salt TEXT NOT NULL,
        farm_name TEXT NOT NULL,
        phone TEXT NOT NULL DEFAULT '',
        created_at INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY,
        account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
        expires_at INTEGER NOT NULL
    );

    CREATE INDEX IF NOT EXISTS sessions_account_id_idx ON sessions(account_id);
`);

const statements = {
    findAccountByUsername: database.prepare(`
        SELECT id, username, password_hash, password_salt, farm_name, phone
        FROM accounts WHERE username = ?
    `),
    findAccountById: database.prepare(`
        SELECT id, username, farm_name, phone FROM accounts WHERE id = ?
    `),
    insertAccount: database.prepare(`
        INSERT INTO accounts (id, username, password_hash, password_salt, farm_name, phone, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `),
    updateFarmName: database.prepare("UPDATE accounts SET farm_name = ? WHERE id = ?"),
    insertSession: database.prepare(`
        INSERT INTO sessions (token_hash, account_id, expires_at) VALUES (?, ?, ?)
    `),
    findSession: database.prepare(`
        SELECT account_id FROM sessions WHERE token_hash = ? AND expires_at > ?
    `),
    deleteSession: database.prepare("DELETE FROM sessions WHERE token_hash = ?"),
    deleteExpiredSessions: database.prepare("DELETE FROM sessions WHERE expires_at <= ?")
};

const scrypt = (password, salt) => new Promise((resolve, reject) => {
    crypto.scrypt(password, salt, 64, (error, key) => {
        if (error) reject(error);
        else resolve(key);
    });
});

function safeEqual(left, right) {
    const a = Buffer.from(left);
    const b = Buffer.from(right);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function sessionTokenHash(token) {
    return crypto.createHash("sha256").update(token).digest("hex");
}

function getCookie(req, name) {
    const cookies = req.headers.cookie || "";
    for (const cookie of cookies.split(";")) {
        const separator = cookie.indexOf("=");
        if (separator < 0) continue;
        if (cookie.slice(0, separator).trim() === name) {
            return decodeURIComponent(cookie.slice(separator + 1).trim());
        }
    }
    return "";
}

function setSessionCookie(res, token) {
    const secure = process.env.NODE_ENV === "production" ? "; Secure" : "";
    res.setHeader(
        "Set-Cookie",
        `cow_farm_session=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${Math.floor(sessionDuration / 1000)}${secure}`
    );
}

function clearSessionCookie(res) {
    res.setHeader(
        "Set-Cookie",
        "cow_farm_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
    );
}

function publicAccount(account) {
    return {
        id: account.id,
        username: account.username,
        farmName: account.farm_name,
        phone: account.phone
    };
}

function requireSameOrigin(req, res, next) {
    const origin = req.get("origin");
    if (origin) {
        let originHost;
        try {
            originHost = new URL(origin).host;
        } catch {
            return res.status(403).json({ error: "คำขอไม่ถูกต้อง" });
        }
        if (originHost !== req.get("host")) {
            return res.status(403).json({ error: "ไม่อนุญาตคำขอจากเว็บไซต์อื่น" });
        }
    }
    next();
}

function currentAccount(req) {
    const token = getCookie(req, "cow_farm_session");
    if (!token) return null;
    const session = statements.findSession.get(sessionTokenHash(token), Date.now());
    return session ? statements.findAccountById.get(session.account_id) || null : null;
}

function createSession(accountId, res) {
    const token = crypto.randomBytes(32).toString("base64url");
    statements.insertSession.run(
        sessionTokenHash(token),
        accountId,
        Date.now() + sessionDuration
    );
    setSessionCookie(res, token);
}

function validateAccountInput({ username, password, farmName, phone }) {
    if (typeof username !== "string" || username.trim().length < 3 || username.trim().length > 60) {
        return "ชื่อผู้ใช้ต้องมีความยาว 3 ถึง 60 ตัวอักษร";
    }
    if (typeof password !== "string" || password.length < 4 || password.length > 256) {
        return "รหัสผ่านต้องมีความยาวอย่างน้อย 4 ตัวอักษร";
    }
    if (typeof farmName !== "string" || !farmName.trim() || farmName.trim().length > 120) {
        return "กรุณากรอกชื่อฟาร์ม";
    }
    if (phone !== undefined && (typeof phone !== "string" || phone.length > 40)) {
        return "รูปแบบเบอร์โทรศัพท์ไม่ถูกต้อง";
    }
    return "";
}

async function insertAccount({ id, username, password, farmName, phone = "" }) {
    const salt = crypto.randomBytes(16);
    const passwordHash = await scrypt(password, salt);
    statements.insertAccount.run(
        id,
        username.trim(),
        passwordHash.toString("hex"),
        salt.toString("hex"),
        farmName.trim(),
        phone.trim(),
        Date.now()
    );
}

app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));
app.use("/api", requireSameOrigin);

app.get("/api/session", (req, res) => {
    statements.deleteExpiredSessions.run(Date.now());
    const account = currentAccount(req);
    if (!account) return res.status(401).json({ error: "ยังไม่ได้เข้าสู่ระบบ" });
    res.json({ account: publicAccount(account) });
});

app.post("/api/register", async (req, res, next) => {
    const { username, password, farmName, phone = "" } = req.body || {};
    const validationError = validateAccountInput({ username, password, farmName, phone });
    if (validationError) return res.status(400).json({ error: validationError });

    try {
        const account = {
            id: crypto.randomUUID(),
            username: username.trim(),
            farmName: farmName.trim(),
            phone: phone.trim()
        };
        await insertAccount({ ...account, password });
        createSession(account.id, res);
        res.status(201).json({ account });
    } catch (error) {
        if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
            return res.status(409).json({ error: "ชื่อผู้ใช้นี้มีแล้ว ลองใช้ชื่ออื่นนะ" });
        }
        next(error);
    }
});

app.post("/api/login", async (req, res, next) => {
    const { username, password } = req.body || {};
    if (typeof username !== "string" || typeof password !== "string") {
        return res.status(400).json({ error: "กรุณากรอกชื่อผู้ใช้และรหัสผ่าน" });
    }
    try {
        const account = statements.findAccountByUsername.get(username.trim());
        if (!account) return res.status(401).json({ error: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" });
        const passwordHash = await scrypt(password, Buffer.from(account.password_salt, "hex"));
        if (!safeEqual(passwordHash, Buffer.from(account.password_hash, "hex"))) {
            return res.status(401).json({ error: "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง" });
        }
        createSession(account.id, res);
        res.json({ account: publicAccount(account) });
    } catch (error) {
        next(error);
    }
});

app.post("/api/logout", (req, res) => {
    const token = getCookie(req, "cow_farm_session");
    if (token) statements.deleteSession.run(sessionTokenHash(token));
    clearSessionCookie(res);
    res.status(204).end();
});

app.patch("/api/account", (req, res) => {
    const account = currentAccount(req);
    if (!account) return res.status(401).json({ error: "กรุณาเข้าสู่ระบบใหม่" });
    const farmName = req.body && req.body.farmName;
    if (typeof farmName !== "string" || !farmName.trim() || farmName.trim().length > 120) {
        return res.status(400).json({ error: "ชื่อฟาร์มต้องมีความยาว 1 ถึง 120 ตัวอักษร" });
    }
    statements.updateFarmName.run(farmName.trim(), account.id);
    res.json({ account: publicAccount(statements.findAccountById.get(account.id)) });
});

app.post("/api/migrate-accounts", async (req, res, next) => {
    const accounts = req.body && req.body.accounts;
    if (!Array.isArray(accounts) || accounts.length > 1000) {
        return res.status(400).json({ error: "ข้อมูลบัญชีเดิมไม่ถูกต้อง" });
    }
    const migratedIds = [];
    const skippedIds = [];
    try {
        for (const legacy of accounts) {
            if (!legacy || typeof legacy.id !== "string" || legacy.id.length > 100 ||
                typeof legacy.password !== "string") {
                return res.status(400).json({ error: "ข้อมูลบัญชีเดิมไม่ถูกต้อง" });
            }
            const validationError = validateAccountInput({
                username: legacy.username,
                password: legacy.password,
                farmName: legacy.farmName || "ฟาร์มของฉัน",
                phone: legacy.phone || ""
            });
            if (validationError) return res.status(400).json({ error: validationError });

            const existingById = statements.findAccountById.get(legacy.id);
            if (existingById) {
                if (existingById.username.toLowerCase() === legacy.username.trim().toLowerCase()) {
                    migratedIds.push(legacy.id);
                } else {
                    skippedIds.push(legacy.id);
                }
                continue;
            }
            if (statements.findAccountByUsername.get(legacy.username.trim())) {
                skippedIds.push(legacy.id);
                continue;
            }

            await insertAccount({
                id: legacy.id,
                username: legacy.username,
                password: legacy.password,
                farmName: legacy.farmName || "ฟาร์มของฉัน",
                phone: legacy.phone || ""
            });
            migratedIds.push(legacy.id);
        }
        res.json({ migratedIds, skippedIds });
    } catch (error) {
        if (error.code === "SQLITE_CONSTRAINT_UNIQUE") {
            return res.status(409).json({ error: "บัญชีบางรายการซ้ำกัน กรุณาตรวจสอบข้อมูลเดิม" });
        }
        next(error);
    }
});

app.get("/", (req, res) => {
    res.set("Cache-Control", "no-store");
    res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/cover-image", (req, res) => {
    res.sendFile(path.join(__dirname, "รูปหน้าปก.jpg"));
});

app.get("/farm-landscape", (req, res) => {
    res.sendFile(path.join(__dirname, "ทุ่งฟาร์มแสนละมุนกับเจ้าวัวน้อย.png"));
});

app.get("/farm-background", (req, res) => {
    res.sendFile(path.join(__dirname, "พื้นหลัง.png"));
});

app.use((error, req, res, next) => {
    if (res.headersSent) return next(error);
    const status = Number.isInteger(error.status) && error.status >= 400 && error.status < 500
        ? error.status
        : 500;
    if (status === 500) console.error(error);
    res.status(status).json({
        error: status === 400
            ? "รูปแบบคำขอไม่ถูกต้อง"
            : "เกิดข้อผิดพลาดในเซิร์ฟเวอร์ กรุณาลองใหม่"
    });
});

app.listen(port, "0.0.0.0", () => {
    console.log(`MY COW FARM พร้อมใช้งานบนพอร์ต ${port}`);
});
