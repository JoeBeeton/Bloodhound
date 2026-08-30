import { useState } from "react";

/**
 * A plain type="password" field with a show/hide toggle - every password field in the app
 * (ChangePasswordModal's three fields first) previously gave no way to check what you'd actually
 * typed short of retyping into a text field elsewhere first, which is exactly the kind of friction
 * that pushes people toward "just paste it and hope." The toggle defaults to hidden, same as a
 * plain password field always has, so nothing about the default behavior changes.
 */
export function PasswordInput({
  id,
  label,
  value,
  onChange,
  autoComplete,
  required,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  autoComplete?: string;
  required?: boolean;
}) {
  const [visible, setVisible] = useState(false);

  return (
    <div>
      <label htmlFor={id} className="mb-1 block font-mono text-xs uppercase tracking-widest text-slate-400">
        {label}
      </label>
      <div className="relative">
        <input
          id={id}
          required={required}
          type={visible ? "text" : "password"}
          autoComplete={autoComplete}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="w-full rounded border border-slate-700 bg-void px-3 py-2 pr-14 font-mono text-sm text-slate-200 outline-none focus:border-neon-cyan"
        />
        <button
          type="button"
          onClick={() => setVisible((v) => !v)}
          aria-label={visible ? `Hide ${label.toLowerCase()}` : `Show ${label.toLowerCase()}`}
          className="absolute right-2 top-1/2 -translate-y-1/2 font-mono text-[10px] uppercase tracking-widest text-slate-500 hover:text-neon-cyan"
        >
          {visible ? "Hide" : "Show"}
        </button>
      </div>
    </div>
  );
}
