'use client';

import { cn } from '@repo/shadcn/lib/utils';
import { KeyboardControlsProps } from '@repo/shadcn/video/player';
import type React from 'react';
import { useEffect, useState } from 'react';

const SUPPORTED_KEYS = [
  ' ',
  'k',
  'm',
  'f',
  'i',
  'ArrowLeft',
  'ArrowRight',
  'Escape',
  '0',
  '1',
  '2',
  '3',
  '4',
  '5',
  '6',
  '7',
  '8',
  '9',
] as const;

type SupportedKey = (typeof SUPPORTED_KEYS)[number];

/**
 * Returns display label and action description for a supported keyboard key.
 *
 * @param key - The pressed keyboard key
 * @param isPlaying
 * @param isMuted
 * @param isFullscreen
 * @returns An object containing the key label and its corresponding action
 */
const getKeyInfo = (
  key: SupportedKey,
  isPlaying: boolean,
  isMuted: boolean,
  isFullscreen: boolean,
): { display: string; description: string } => {
  switch (key) {
    case ' ':
    case 'k':
      return {
        display: key === ' ' ? 'Space' : 'K',
        description: isPlaying ? 'Played' : 'Paused',
      };
    case 'm':
      return {
        display: 'M',
        description: isMuted ? 'Unmute' : 'Mute',
      };
    case 'f':
      return {
        display: 'F',
        description: isFullscreen ? 'Exit Fullscreen' : 'Fullscreen',
      };
    case 'ArrowLeft':
      return {
        display: '←',
        description: 'Back 10s',
      };
    case 'ArrowRight':
      return {
        display: '→',
        description: 'Forward 10s',
      };
    case 'Escape':
      return {
        display: 'Esc',
        description: 'Exit',
      };
    default:
      return {
        display: key,
        description: `${key}0% of video`,
      };
  }
};

/**
 * KeyboardControls Component
 *
 * Shows temporary overlay with key name and action when user triggers a
 * supported keyboard shortcut while interacting with the video player.
 */
export const KeyboardControls: React.FC<KeyboardControlsProps> = ({
  isPlaying,
  isMuted,
  isFullscreen,
}) => {
  const [activeKey, setActiveKey] = useState<SupportedKey | null>(null);
  const [showKeyHint, setShowKeyHint] = useState(false);
  const [keyHintTimeout, setKeyHintTimeout] = useState<NodeJS.Timeout | null>(
    null,
  );

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ignore input fields and modified key presses
      if (
        document.activeElement instanceof HTMLInputElement ||
        document.activeElement instanceof HTMLTextAreaElement ||
        e.ctrlKey ||
        e.altKey ||
        e.metaKey
      )
        return;

      if (SUPPORTED_KEYS.includes(e.key as SupportedKey)) {
        setActiveKey(e.key as SupportedKey);
        setShowKeyHint(true);

        if (keyHintTimeout) clearTimeout(keyHintTimeout);

        const timeout = setTimeout(() => {
          setShowKeyHint(false);
          setActiveKey(null);
        }, 1000);

        setKeyHintTimeout(timeout);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
      if (keyHintTimeout) clearTimeout(keyHintTimeout);
    };
  }, [keyHintTimeout]);

  if (!showKeyHint || !activeKey) return null;

  const { display, description } = getKeyInfo(
    activeKey,
    isPlaying,
    isMuted,
    isFullscreen,
  );

  return (
    <div
      className={cn(
        'absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2',
        'bg-card-foreground rounded px-4 py-2 text-white text-center transition-opacity duration-300',
        showKeyHint ? 'opacity-100' : 'opacity-0',
      )}
    >
      <div className="flex gap-2 items-center justify-center">
        <div className="font-mono text-lg font-black">{display}</div>
        <div className="text-xs">{description}</div>
      </div>
    </div>
  );
};
