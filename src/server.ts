import express from "express";
import path from "path";
import { api } from "./routes";
import { SECURE_MODE, PORT, HOST } from "./config";

const app = express();
app.use(express.json());

// Serve the single-page UI.
app.use(express.static(path.join(__dirname, "..", "public")));

app.use("/api", api);

// GUARDRAIL: bind to loopback only. This server must never be reachable from
// another machine. All data is fake and seeded; there are no outbound calls.
app.listen(PORT, HOST, () => {
  const banner = SECURE_MODE ? "SECURE_MODE (all fixes applied)" : "VULNERABLE (chain works)";
  console.log("========================================================");
  console.log("  Chained Attack Demo  --  FOR SECURITY EDUCATION ONLY");
  console.log("  Intentionally vulnerable. Do not deploy.");
  console.log(`  Mode: ${banner}`);
  console.log(`  Open: http://${HOST}:${PORT}`);
  console.log("========================================================");
});
