import type { ReactNode } from "react";

/** Vertically centers a short block within Shell's now top-aligned <main> - for login, transient loading/auth states, and full-page errors. */
export function CenteredState({ children }: { children: ReactNode }) {
  return <div className="flex w-full flex-1 flex-col items-center justify-center text-center">{children}</div>;
}
