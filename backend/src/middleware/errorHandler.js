/**
 * Centralized async error handler for Express routes.
 */
function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

function errorHandler(err, _req, res, _next) {
  console.error("[API Error]", err);
  const status = err.status || 500;
  res.status(status).json({
    ok: false,
    error: err.message || "Internal server error",
  });
}

module.exports = { asyncHandler, errorHandler };
