import { useEffect, useState } from "react";
import { apiFetch } from "../lib/apiClient";

/**
 * Fetches a screenshot via apiFetch (not a plain `<img src>` pointed at the API directly -
 * the endpoint requires the bearer token apiFetch attaches, which a bare `<img>` tag has no
 * way to send) and renders it from an object URL. Revokes the object URL on unmount/src
 * change so repeatedly opening/closing a target detail page doesn't leak blob memory.
 */
export function ScreenshotThumbnail({ src, alt }: { src: string; alt: string }) {
  const [objectUrl, setObjectUrl] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    let currentUrl: string | null = null;
    setFailed(false);

    apiFetch(src)
      .then((res) => {
        if (!res.ok) throw new Error("screenshot fetch failed");
        return res.blob();
      })
      .then((blob) => {
        if (cancelled) return;
        currentUrl = URL.createObjectURL(blob);
        setObjectUrl(currentUrl);
      })
      .catch(() => {
        if (!cancelled) setFailed(true);
      });

    return () => {
      cancelled = true;
      if (currentUrl) URL.revokeObjectURL(currentUrl);
    };
  }, [src]);

  if (failed) {
    return <span className="font-mono text-[10px] text-slate-600">—</span>;
  }
  if (!objectUrl) {
    return <span className="block h-12 w-16 animate-pulse rounded bg-slate-800" />;
  }
  return (
    <img
      src={objectUrl}
      alt={alt}
      className="h-12 w-16 rounded border border-slate-700 object-cover object-top"
    />
  );
}
