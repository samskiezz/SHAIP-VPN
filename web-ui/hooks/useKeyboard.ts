import { useEffect } from 'react';

type Handler = (e: KeyboardEvent) => void;

/** Bind a shortcut like "mod+k" (mod = Ctrl or Cmd). */
export function useKeyboard(combo: string, handler: Handler) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const parts: string[] = [];
      if (e.ctrlKey || e.metaKey) parts.push('mod');
      if (e.shiftKey) parts.push('shift');
      if (e.altKey) parts.push('alt');
      parts.push(e.key.toLowerCase());
      if (parts.join('+') === combo.toLowerCase()) {
        e.preventDefault();
        handler(e);
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [combo, handler]);
}
