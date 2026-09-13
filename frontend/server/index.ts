import express from "express";
import { createServer } from "http";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function startServer() {
  const app = express();
  const server = createServer(app);
  const apiTarget = (process.env.BACKEND_API_URL || "http://127.0.0.1:5000").replace(/\/$/, "");

  app.all("/api/*", async (req, res) => {
    try {
      const headers = new Headers();
      Object.entries(req.headers).forEach(([name, value]) => {
        if (name !== "host" && typeof value === "string") headers.set(name, value);
      });
      const body = ["GET", "HEAD"].includes(req.method) ? undefined : await new Promise<Buffer>((resolve, reject) => {
        const chunks: Buffer[] = [];
        req.on("data", (chunk) => chunks.push(Buffer.from(chunk)));
        req.on("end", () => resolve(Buffer.concat(chunks)));
        req.on("error", reject);
      });
      const response = await fetch(`${apiTarget}${req.originalUrl}`, { method: req.method, headers, body });
      res.status(response.status);
      response.headers.forEach((value, name) => res.setHeader(name, value));
      res.send(Buffer.from(await response.arrayBuffer()));
    } catch (error) {
      console.error("API proxy error", error);
      res.status(502).json({ detail: "Local API unavailable" });
    }
  });

  // Serve static files from dist/public in production
  const staticPath =
    process.env.NODE_ENV === "production"
      ? path.resolve(__dirname, "public")
      : path.resolve(__dirname, "..", "dist", "public");

  app.use(express.static(staticPath));

  // Handle client-side routing - serve index.html for all routes
  app.get("*", (_req, res) => {
    res.sendFile(path.join(staticPath, "index.html"));
  });

  const port = Number(process.env.PORT) || 3000;
  const host = process.env.HOST || "0.0.0.0";

  server.listen(port, host, () => {
    console.log(`VEYRONIX Server running on http://${host}:${port}/ (LAN-ready)`);
  });
}

startServer().catch(console.error);
