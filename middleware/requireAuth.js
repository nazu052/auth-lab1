const jwt = require("jsonwebtoken");

function requireAuth(req, res, next) {
    const token = req.cookies?.accessToken;

    if (!token) {
        return res.status(401).json({
            message: "Нэвтрэх шаардлагатай."
        });
    }

    try {
        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        if (decoded.type !== "access") {
            return res.status(401).json({
                message: "Access token буруу байна."
            });
        }

        req.user = {
            id: decoded.sub
        };

        next();
    } catch (error) {
        return res.status(401).json({
            message: "Токен хүчингүй эсвэл хугацаа дууссан."
        });
    }
}

module.exports = requireAuth;