"use client";

import { useState } from "react";

export function WaitlistForm({ reportId }: { reportId: string }) {
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<"idle" | "saving" | "saved" | "error">("idle");

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setStatus("saving");
    const response = await fetch("/api/waitlist", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, reportId })
    });
    setStatus(response.ok ? "saved" : "error");
  }

  return (
    <form className="waitlist-form" onSubmit={onSubmit}>
      <input
        type="email"
        required
        placeholder="you@example.com"
        value={email}
        onChange={(event) => setEmail(event.target.value)}
      />
      <button className="primary-button" type="submit" disabled={status === "saving"}>
        {status === "saving" ? "Saving..." : "Reserve access"}
      </button>
      <p className="scan-note">
        We store your email so we can contact you about deploy-time rescans and deletion requests.
      </p>
      {status === "saved" ? <p className="form-success">You're on the list.</p> : null}
      {status === "error" ? <p className="form-error">Could not save that email.</p> : null}
    </form>
  );
}
