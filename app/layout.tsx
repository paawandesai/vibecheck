import type { Metadata } from "next";
import Script from "next/script";
import { PendoInitializer } from "@/components/PendoInitializer";
import { scanConfig } from "@/lib/env";
import "./globals.css";

export const metadata: Metadata = {
  title: "VibeCheck",
  description: "Read-only security reports for vibe-coded apps.",
  robots: {
    index: true,
    follow: true
  }
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <head>
        {scanConfig.pendoApiKey ? (
          <Script id="pendo-install" strategy="beforeInteractive">{`
(function(apiKey){
    (function(p,e,n,d,o){var v,w,x,y,z;o=p[d]=p[d]||{};o._q=o._q||[];
    v=['initialize','identify','updateOptions','pageLoad','track', 'trackAgent'];for(w=0,x=v.length;w<x;++w)(function(m){
    o[m]=o[m]||function(){o._q[m===v[0]?'unshift':'push']([m].concat([].slice.call(arguments,0)));};})(v[w]);
    y=e.createElement(n);y.async=!0;y.src='https://cdn.pendo.io/agent/static/'+apiKey+'/pendo.js';
    z=e.getElementsByTagName(n)[0];z.parentNode.insertBefore(y,z);})(window,document,'script','pendo');
})('${scanConfig.pendoApiKey}');
`}</Script>
        ) : null}
      </head>
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
        {scanConfig.pendoApiKey ? <PendoInitializer /> : null}
        {children}
      </body>
    </html>
  );
}
