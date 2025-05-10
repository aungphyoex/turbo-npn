'use client';

import { Button } from '@repo/shadcn/button';
import { useMobile } from '@repo/shadcn/hooks/use-mobile';
import { cn, formatTime } from '@repo/shadcn/lib/utils';
import { VideoControlsProps } from '@repo/shadcn/video/player';
import VideoResizer from '@repo/shadcn/video/video-resizer';
import {
  FastForward,
  Maximize,
  Pause,
  Play,
  Rewind,
  Volume2,
  VolumeX,
} from 'lucide-react';
import { useCallback, useEffect, useRef, useState } from 'react';

export const VideoControls: React.FC<VideoControlsProps> = ({
  isPlaying,
  isMuted,
  currentTime,
  duration,
  playbackRate,
  sizeMode,
  setSizeMode,
  onPlayPause,
  onMute,
  onSkipBackward,
  onSkipForward,
  onFullscreen,
  onPlaybackRateChange,
}) => {
  const isMobile = useMobile();

  const VolumeIcon = useCallback(() => {
    return isMuted ? (
      <VolumeX className="size-4" />
    ) : (
      <Volume2 className="size-4" />
    );
  }, [isMuted]);

  return (
    <div className="flex items-center justify-between w-full py-1 text-neutral-300 text-sm ">
      {/* Left Controls */}
      <div className="flex items-center space-x-2">
        <IconButton onClick={onPlayPause} aria-label="Play/Pause">
          {isPlaying ? (
            <Pause className="size-4" />
          ) : (
            <Play className="size-4" />
          )}
        </IconButton>

        <IconButton onClick={onSkipBackward} aria-label="Rewind 10s">
          <Rewind className="size-4" />
        </IconButton>

        <IconButton onClick={onSkipForward} aria-label="Forward 10s">
          <FastForward className="size-4" />
        </IconButton>

        <div className="flex items-center text-xs">
          <span className="px-1">{formatTime(currentTime)}</span>
          <span>/</span>
          <span className="px-1">{formatTime(duration)}</span>
        </div>
      </div>

      {/* Right Controls */}
      <div className="flex items-center space-x-2">
        <PlaybackRateMenu
          playbackRate={playbackRate}
          onPlaybackRateChange={onPlaybackRateChange}
        />

        {!isMobile && (
          <IconButton onClick={onMute} aria-label="Toggle Mute">
            <VolumeIcon />
          </IconButton>
        )}

        <VideoResizer sizeMode={sizeMode} setSizeMode={setSizeMode} />

        <IconButton onClick={onFullscreen} aria-label="Fullscreen">
          <Maximize className="size-4" />
        </IconButton>
      </div>
    </div>
  );
};

const IconButton: React.FC<React.ButtonHTMLAttributes<HTMLButtonElement>> = ({
  children,
  ...props
}) => (
  <Button
    variant="ghost"
    size="icon"
    className="size-6 focus:outline-none focus-visible:ring-0 text-secondary dark:text-secondary-foreground"
    {...props}
  >
    {children}
  </Button>
);

interface PlaybackRateMenuProps {
  playbackRate: number;
  onPlaybackRateChange: (rate: number) => void;
}

const PlaybackRateMenu: React.FC<PlaybackRateMenuProps> = ({
  playbackRate,
  onPlaybackRateChange,
}) => {
  const [isOpen, setIsOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);
  const rates = [0.5, 1, 1.5, 2];

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        setIsOpen(false);
      }
    };

    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, []);

  return (
    <div className="relative" ref={menuRef}>
      <Button
        size="icon"
        variant="ghost"
        className="flex items-center bg-primary/80 rounded size-6 hover:bg-primary transition-colors focus:outline-none focus-visible:ring-0"
        onClick={() => setIsOpen(!isOpen)}
      >
        <span className="text-xs">{playbackRate}x</span>
      </Button>

      {isOpen && (
        <div className="absolute bottom-full mb-1 right-0 bg-card-foreground rounded overflow-hidden shadow-lg z-50">
          <div className="p-2 w-20">
            {rates.map((rate) => (
              <button
                key={rate}
                className={cn(
                  'w-full px-4 py-1 text-xs text-left hover:bg-primary/50 hover:text-neutral-100',
                  rate === playbackRate && 'bg-primary/80 text-neutral-200',
                )}
                onClick={() => {
                  onPlaybackRateChange(rate);
                  setIsOpen(false);
                }}
              >
                {rate}x
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
