'use client';

import type React from 'react';
import { useRef } from 'react';

interface VideoTimelineProps {
  currentTime: number;
  duration: number;
  onSeek: (time: number) => void;
}

export const VideoTimeline: React.FC<VideoTimelineProps> = ({
  currentTime,
  duration,
  onSeek,
}) => {
  const progressBarRef = useRef<HTMLDivElement>(null);

  // Calculate progress percentage
  const progressPercentage = duration > 0 ? (currentTime / duration) * 100 : 0;

  // Handle click on progress bar
  const handleProgressBarClick = (e: React.MouseEvent<HTMLDivElement>) => {
    if (!progressBarRef.current) return;

    const rect = progressBarRef.current.getBoundingClientRect();
    const clickPosition = (e.clientX - rect.left) / rect.width;
    const seekTime = clickPosition * duration;

    onSeek(seekTime);
  };

  // Handle mouse down on progress bar
  const handleMouseDown = (e: React.MouseEvent<HTMLDivElement>) => {
    // Also update position immediately on click
    if (progressBarRef.current) {
      const rect = progressBarRef.current.getBoundingClientRect();
      const clickPosition = (e.clientX - rect.left) / rect.width;
      const seekTime = clickPosition * duration;
      onSeek(seekTime);
    }

    const handleMouseUp = () => {
      document.removeEventListener('mouseup', handleMouseUp);
      document.removeEventListener('mousemove', handleGlobalMouseMove);
    };

    const handleGlobalMouseMove = (e: MouseEvent) => {
      if (!progressBarRef.current) return;

      const rect = progressBarRef.current.getBoundingClientRect();
      const hoverPos = Math.max(
        0,
        Math.min(1, (e.clientX - rect.left) / rect.width),
      );
      const seekTime = hoverPos * duration;
      onSeek(seekTime);
    };

    document.addEventListener('mouseup', handleMouseUp);
    document.addEventListener('mousemove', handleGlobalMouseMove);
  };

  // Handle touch events for mobile
  const handleTouchStart = (e: React.TouchEvent<HTMLDivElement>) => {
    if (!progressBarRef.current) return;
    const touchClientX = e.touches?.[0]?.clientX ?? 0;
    const rect = progressBarRef.current.getBoundingClientRect();
    const touchPosition = (touchClientX - rect.left) / rect.width;
    const seekTime = touchPosition * duration;
    onSeek(seekTime);

    const handleTouchMove = (e: TouchEvent) => {
      if (!progressBarRef.current) return;

      const rect = progressBarRef.current.getBoundingClientRect();
      const touchPos = Math.max(
        0,
        Math.min(1, (touchClientX - rect.left) / rect.width),
      );
      const seekTime = touchPos * duration;
      onSeek(seekTime);
    };

    const handleTouchEnd = () => {
      document.removeEventListener('touchmove', handleTouchMove);
      document.removeEventListener('touchend', handleTouchEnd);
    };

    document.addEventListener('touchmove', handleTouchMove);
    document.addEventListener('touchend', handleTouchEnd);
  };

  return (
    <div className="relative w-full mb-2">
      {/* Progress bar */}
      <div
        ref={progressBarRef}
        className="w-full h-1.5 bg-gray-700 cursor-pointer group"
        onClick={handleProgressBarClick}
        onMouseDown={handleMouseDown}
        onTouchStart={handleTouchStart}
      >
        {/* Buffered progress */}
        <div
          className="h-full bg-gray-500"
          style={{ width: `${Math.min((currentTime / duration) * 110, 100)}%` }}
        />

        {/* Progress indicator */}
        <div
          className="h-full bg-primary absolute top-0 left-0"
          style={{ width: `${progressPercentage}%` }}
        />

        {/* Progress handle */}
        <div
          className="absolute top-1/2 rounded-full -translate-y-1/2 size-3 bg-primary border-2 border-white opacity-0 group-hover:opacity-100 transition-opacity"
          style={{
            left: `${progressPercentage}%`,
            transform: 'translate(-50%, 0%)',
          }}
        />
      </div>
    </div>
  );
};
