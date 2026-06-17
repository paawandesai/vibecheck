"use client";

import { useEffect } from "react";

function getOrCreateVisitorId(): string {
  const key = "vc_visitor_id";
  let id = localStorage.getItem(key);
  if (!id) {
    id = crypto.randomUUID();
    localStorage.setItem(key, id);
  }
  return id;
}

export function PendoInitializer() {
  useEffect(() => {
    if (typeof pendo === "undefined" || !pendo.initialize) return;
    pendo.initialize({
      visitor: { id: getOrCreateVisitorId() },
    });
  }, []);

  return null;
}
