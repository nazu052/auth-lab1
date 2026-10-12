function isValidPassword(password) {
    return (
        typeof password === "string" &&
        password.length >= 8 &&
        /[A-Z]/.test(password) &&
        /[a-z]/.test(password) &&
        /[0-9]/.test(password)
    );
}

require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");

const User = require("./models/User");
const RefreshToken = require("./models/RefreshToken");
const requireAuth = require("./middleware/requireAuth");

const app = express();

app.use(express.json());
app.use(cookieParser());

const PORT = process.env.PORT || 3000;

const ACCESS_TOKEN_MS = 15 * 60 * 1000;
const REFRESH_TOKEN_MS = 7 * 24 * 60 * 60 * 1000;

const cookieOptions = {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/"
};

function isValidPassword(password) {
    return (
        typeof password === "string" &&
        password.length >= 8 &&
        /[A-Z]/.test(password) &&
        /[a-z]/.test(password) &&
        /[0-9]/.test(password)
    );
}

function hashToken(token) {
    return crypto
        .createHash("sha256")
        .update(token)
        .digest("hex");
}

function createAccessToken(userId) {
    return jwt.sign(
        {
            type: "access"
        },
        process.env.JWT_SECRET,
        {
            subject: userId.toString(),
            expiresIn: "15m"
        }
    );
}

function createRefreshToken(userId) {
    return jwt.sign(
        {
            type: "refresh"
        },
        process.env.REFRESH_TOKEN_SECRET,
        {
            subject: userId.toString(),
            expiresIn: "7d"
        }
    );
}

function setAuthCookies(res, accessToken, refreshToken) {
    res.cookie("accessToken", accessToken, {
        ...cookieOptions,
        maxAge: ACCESS_TOKEN_MS
    });

    res.cookie("refreshToken", refreshToken, {
        ...cookieOptions,
        maxAge: REFRESH_TOKEN_MS
    });
}

function clearAuthCookies(res) {
    res.clearCookie("accessToken", cookieOptions);
    res.clearCookie("refreshToken", cookieOptions);
}


// REGISTER - Шинэ хэрэглэгч бүртгэх
app.post("/api/register", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({
                message: "Username болон password шаардлагатай."
            });
        }

        const existingUser = await User.findOne({ username });

        if (existingUser) {
            return res.status(409).json({
                message: "Энэ username аль хэдийн бүртгэгдсэн байна."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        const user = await User.create({
            username,
            password: hashedPassword
        });

        return res.status(201).json({
            message: "Хэрэглэгч амжилттай бүртгэгдлээ.",
            username: user.username
        });
    } catch (error) {
        console.error(error);

        return res.status(500).json({
            message: "Серверийн алдаа."
        });
    }
});

// LOGIN
app.post("/api/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        if (
            typeof username !== "string" ||
            typeof password !== "string"
        ) {
            return res.status(400).json({
                message: "Username болон password шаардлагатай."
            });
        }

        const user = await User.findOne({ username });

        if (!user) {
            return res.status(401).json({
                message: "Нэвтрэх мэдээлэл буруу байна."
            });
        }

        const passwordMatches = await bcrypt.compare(
            password,
            user.password
        );

        if (!passwordMatches) {
            return res.status(401).json({
                message: "Нэвтрэх мэдээлэл буруу байна."
            });
        }

        const accessToken = createAccessToken(user._id);
        const refreshToken = createRefreshToken(user._id);

        await RefreshToken.create({
            userId: user._id,
            tokenHash: hashToken(refreshToken),
            expiresAt: new Date(Date.now() + REFRESH_TOKEN_MS)
        });

        setAuthCookies(res, accessToken, refreshToken);

        return res.json({
            message: "Амжилттай нэвтэрлээ."
        });
    } catch (error) {
        console.error(error);

        return res.status(500).json({
            message: "Серверийн алдаа."
        });
    }
});

// CHANGE PASSWORD
app.post(
    "/api/change-password",
    requireAuth,
    async (req, res) => {
        try {
            const { oldPassword, newPassword } = req.body;

            if (
                typeof oldPassword !== "string" ||
                typeof newPassword !== "string"
            ) {
                return res.status(400).json({
                    message: "Хуучин болон шинэ нууц үг шаардлагатай."
                });
            }

            if (!isValidPassword(newPassword)) {
                return res.status(400).json({
                    message:
                        "Нууц үг 8-аас доошгүй тэмдэгттэй бөгөөд том үсэг, жижиг үсэг, тоо агуулсан байх ёстой."
                });
            }

            const user = await User.findById(req.user.id);

            if (!user) {
                return res.status(404).json({
                    message: "Хэрэглэгч олдсонгүй."
                });
            }

            const passwordMatches = await bcrypt.compare(
                oldPassword,
                user.password
            );

            if (!passwordMatches) {
                return res.status(400).json({
                    message: "Хуучин нууц үг буруу байна."
                });
            }

            user.password = await bcrypt.hash(newPassword, 12);

            await user.save();

            // Бусад refresh token-уудыг хүчингүй болгоно.
            await RefreshToken.updateMany(
                {
                    userId: user._id,
                    revoked: false
                },
                {
                    $set: { revoked: true }
                }
            );

            clearAuthCookies(res);

            return res.json({
                message:
                    "Нууц үг амжилттай солигдлоо. Дахин нэвтэрнэ үү."
            });
        } catch (error) {
            console.error(error);

            return res.status(500).json({
                message: "Серверийн алдаа."
            });
        }
    }
);

// REFRESH ACCESS TOKEN
app.post("/api/refresh", async (req, res) => {
    try {
        const token = req.cookies?.refreshToken;

        if (!token) {
            return res.status(401).json({
                message: "Refresh token олдсонгүй."
            });
        }

        let decoded;

        try {
            decoded = jwt.verify(
                token,
                process.env.REFRESH_TOKEN_SECRET
            );
        } catch {
            clearAuthCookies(res);

            return res.status(401).json({
                message: "Refresh token хүчингүй эсвэл хугацаа дууссан."
            });
        }

        if (decoded.type !== "refresh") {
            clearAuthCookies(res);

            return res.status(401).json({
                message: "Refresh token буруу байна."
            });
        }

        const tokenHash = hashToken(token);

        const savedToken = await RefreshToken.findOne({
            userId: decoded.sub,
            tokenHash,
            revoked: false,
            expiresAt: { $gt: new Date() }
        });

        if (!savedToken) {
            clearAuthCookies(res);

            return res.status(401).json({
                message: "Refresh token хүчингүй болсон байна."
            });
        }

        // Нэг refresh token-ийг дахин ашиглуулахгүй.
        savedToken.revoked = true;
        await savedToken.save();

        const user = await User.findById(decoded.sub);

        if (!user) {
            clearAuthCookies(res);

            return res.status(401).json({
                message: "Хэрэглэгч олдсонгүй."
            });
        }

        const newAccessToken = createAccessToken(user._id);
        const newRefreshToken = createRefreshToken(user._id);

        await RefreshToken.create({
            userId: user._id,
            tokenHash: hashToken(newRefreshToken),
            expiresAt: new Date(Date.now() + REFRESH_TOKEN_MS)
        });

        setAuthCookies(res, newAccessToken, newRefreshToken);

        return res.json({
            message: "Token амжилттай шинэчлэгдлээ."
        });
    } catch (error) {
        console.error(error);

        return res.status(500).json({
            message: "Серверийн алдаа."
        });
    }
});

// LOGOUT
app.post("/api/logout", async (req, res) => {
    try {
        const token = req.cookies?.refreshToken;

        if (token) {
            try {
                const decoded = jwt.verify(
                    token,
                    process.env.REFRESH_TOKEN_SECRET
                );

                if (decoded.type === "refresh") {
                    await RefreshToken.updateOne(
                        {
                            userId: decoded.sub,
                            tokenHash: hashToken(token),
                            revoked: false
                        },
                        {
                            $set: { revoked: true }
                        }
                    );
                }
            } catch {
                // Хүчингүй эсвэл хугацаа дууссан токеныг
                // мөн cookie-оос цэвэрлэнэ.
            }
        }

        clearAuthCookies(res);

        return res.json({
            message: "Амжилттай гарлаа."
        });
    } catch (error) {
        console.error(error);

        return res.status(500).json({
            message: "Серверийн алдаа."
        });
    }
});

// Protected test endpoint
app.get("/api/profile", requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id)
            .select("_id username");

        if (!user) {
            return res.status(404).json({
                message: "Хэрэглэгч олдсонгүй."
            });
        }

        return res.json({ user });
    } catch (error) {
        console.error(error);

        return res.status(500).json({
            message: "Серверийн алдаа."
        });
    }
});

async function startServer() {
    try {
        if (
            !process.env.MONGO_URL ||
            !process.env.JWT_SECRET ||
            !process.env.REFRESH_TOKEN_SECRET
        ) {
            throw new Error(
                ".env файл дахь шаардлагатай тохиргоонууд дутуу байна."
            );
        }

        await mongoose.connect(process.env.MONGO_URL);

        console.log("MongoDB холбогдлоо.");

        app.listen(PORT, () => {
            console.log(`Server http://localhost:${PORT}`);
        });
    } catch (error) {
        console.error("Сервер эхлүүлэхэд алдаа:", error.message);
        process.exit(1);
    }
}

startServer();