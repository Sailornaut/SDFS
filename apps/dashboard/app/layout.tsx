import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = { title: "SecureDFS Control Plane", description: "Agent approvals and policy control" };

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
