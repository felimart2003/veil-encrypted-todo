import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "VEIL — Public list. Private meaning.",
  description: "A personal to-do list in plain sight. Browser-side encryption keeps the meaning behind a secret key.",
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
