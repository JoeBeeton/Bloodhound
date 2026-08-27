import { useEffect, useState } from "react";
import { apiFetch } from "../lib/apiClient";
import { Modal } from "./Modal";

const SIZE_CLASSES = {
  small: "h-12 w-16",
  large: "h-24 w-32",
} as const;

/**
 * Fetches a screenshot via apiFetch (not a plain `<img src>` pointed at the API directly -
 * the endpoint requires the bearer token apiFetch attaches, which a bare `<img>` tag has no
 * way to send) and renders it from an object URL. Revokes the object URL on unmount/src
 * change so repeatedly opening/closing a target detail page doesn't leak blob memory.
 *
 * Clicking the thumbnail opens the same already-fetched image at full size in a modal - the
 * "thumbnail" is just a small CSS-scaled rendering of the one screenshot this component holds,
 * not a separately-generated smaller image, so the enlarged view needs no extra request.
 */
export function ScreenshotThumbnail({
  src,
  alt,
  size = "small",
}: {
  src: string;
  alt: string;
  /** "large" for the real-domain hero row in BrandProtectionPanel - everywhere else (candidate table rows) wants "small" (the default). */
  size?: keyof typeof SIZE_CLASSES;
}) {
  const [objectUrl, setObjectUrl] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const sizeClass = SIZE_CLASSES[size];

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
    return <span className={`block animate-pulse rounded bg-slate-800 ${sizeClass}`} />;
  }
  return (
    <>
      <button
        type="button"
        onClick={() => setExpanded(true)}
        className="block cursor-zoom-in rounded border border-slate-700 transition hover:border-neon-cyan/50"
        aria-label={`Enlarge ${alt}`}
      >
        <img src={objectUrl} alt={alt} className={`rounded object-cover object-top ${sizeClass}`} />
      </button>
      {expanded && (
        <Modal title={alt} onClose={() => setExpanded(false)} wide>
          <img src={objectUrl} alt={alt} className="w-full rounded border border-slate-700" />
        </Modal>
      )}
    </>
  );
}
