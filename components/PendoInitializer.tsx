"use client";

import { useEffect } from "react";

export function PendoInitializer() {
  useEffect(() => {
    if (typeof pendo === "undefined" || !pendo.initialize) return;
    pendo.initialize({
      visitor: {
        id: "",
      },
    });
  }, []);

  return null;
}
