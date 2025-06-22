'use client';

import { Moon, Sun } from 'lucide-react';
import { useTheme } from 'next-themes';
import * as React from 'react';
import { useEffect, useState } from 'react';

export function ModeSwitcher() {
  const { setTheme, resolvedTheme } = useTheme();

  const isDark = resolvedTheme === 'dark';

  const toggleTheme = React.useCallback(async () => {
    // setTheme(resolvedTheme === 'dark' ? 'light' : 'dark');
    if (!document.startViewTransition)
      return setTheme(resolvedTheme === 'dark' ? 'light' : 'dark');
    await document.startViewTransition(() =>
      setTheme(resolvedTheme === 'dark' ? 'light' : 'dark'),
    ).ready;
  }, [resolvedTheme, setTheme]);

  const [mounted, setMounted] = useState(false);

  // useEffect only runs on the client, so now we can safely show the UI
  useEffect(() => {
    setMounted(true);
  }, []);

  if (!mounted) {
    return null;
  }
  return (
    <button
      onClick={toggleTheme}
      className={`relative flex h-8 w-8 items-center justify-center rounded-full text-[var(--text-color-primary)] hover:opacity-80 transition-opacity overflow-hidden`}
    >
      <Sun
        className={`absolute h-5 w-5 transition-all duration-300 ease-[cubic-bezier(0.34,1.56,0.64,1)] ${
          resolvedTheme === 'light'
            ? 'scale-100 translate-y-0 opacity-100'
            : 'scale-50 translate-y-5 opacity-0'
        }`}
      />
      <Moon
        className={`absolute h-5 w-5 transition-all duration-300 ease-[cubic-bezier(0.34,1.56,0.64,1)] ${
          resolvedTheme === 'dark'
            ? 'scale-100 translate-y-0 opacity-100'
            : 'scale-50 translate-y-5 opacity-0'
        }`}
      />
    </button>
  );
}
