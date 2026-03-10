/**
 * middleware/requireAdmin.js
 * 
 * Runs AFTER authentication middleware.
 * Checks if the logged-in user has role "admin".
 * If yes - continues to route handler.
 * If no - returns 403 Forbidden.
 * 
 * Usage:
 * import authenticate from "./authenticate.js";
 * import requireAdmin from "./requireAdmin.js";
 * router.get("/admin-route", authenticate, requireAdmin,async (req, res) => {...})
 */

import User from "../models/User.js";

const requireAdmin = async (req, res, next) => {
    try {
        //req.user.id set by authenticate middleware
        //Look up the full user record to get their role
        const user = await User.findById(req.user.id).select("role");

        if (!user) {
            return res.status(401).json({error: "User not found" });
        }

        if (user.role !== "admin") {
            return res.status(403).json({error: "Admin access required"});
        }
        // Attach role to req.user for use in route if needed
        req.user.role = user.role;

        next();
    } catch (err) {
        console.error("requireAdmin error:", err);
        res.status(500).json({error: "Authorization check failed" });
    }

};
export default requireAdmin;
