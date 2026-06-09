"use client";

import { useEffect } from "react";

export function PendoInitializer() {
  useEffect(() => {
    pendo.initialize({
      visitor: {
        id: "",
      },
    });
  }, []);

  return null;
}
