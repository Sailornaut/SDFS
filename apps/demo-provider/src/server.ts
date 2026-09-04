import "dotenv/config";
import { createProviderApp, createSdfsGrantClient } from "./app.js";

const apiKey = process.env.SDFS_PROVIDER_API_KEY;
if (!apiKey) throw new Error("SDFS_PROVIDER_API_KEY is required. Run pnpm demo:setup and add the generated key to .env.");
const app = createProviderApp(createSdfsGrantClient({ apiUrl: process.env.SDFS_API_URL ?? "http://localhost:4100", apiKey }));
await app.listen({ port: Number(process.env.PROVIDER_PORT ?? 4300), host: process.env.HOST ?? "0.0.0.0" });
