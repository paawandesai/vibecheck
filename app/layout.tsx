import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "VibeCheck",
  description: "Read-only security reports for vibe-coded apps.",
  robots: {
    index: false,
    follow: false
  }
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>
        <header className="site-header">
          <a className="brand" href="/">
            <span className="brand-mark">VC</span>
            <span>VibeCheck</span>
          </a>
          <nav aria-label="Main navigation">
            <a href="/responsible-use">Responsible use</a>
          </nav>
        </header>
        {children}
      </body>
    </html>
  );
}
