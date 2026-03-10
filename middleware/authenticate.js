/**
 * middleware/authenticate.js
 * 
 * checks if the user is logged in via session.
 * If yes  - attaches req.user.id and continues to the route.
 * If no   - returns 401 and blocks the request.
 */
const authenticate = (req, res, next) => {
    // Check if session exists and has a userID
    if (!req.session || !req.session.userId) {
        return res.status(401).json({ error: "Authentication required. Please log in." });
    }
    // Attach user info so routes can access req.user.id
    req.user = {
        id: req.session.userId.toString()
    };
    // Move on to the next middleware or route handler
    next();

};
export default authenticate;
