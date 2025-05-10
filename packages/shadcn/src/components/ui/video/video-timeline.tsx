'use client';

import { formatTime } from '@repo/shadcn/lib/video-utils';
import { DualRangeSlider } from '@repo/shadcn/range-slider';
import type React from 'react';
import { useEffect, useState } from 'react';

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
  const [widthPercentage, setWidthPercentage] = useState(0);

  // Update slider when video time changes (e.g., via play)
  useEffect(() => {
    if (duration > 0) {
      const newPercentage = (currentTime / duration) * 100;
      setWidthPercentage(newPercentage);
    }
  }, [currentTime, duration]);

  const handleSliderChange = ([newPercentage]: number[]) => {
    if (newPercentage != null) {
      setWidthPercentage(newPercentage);
      onSeek((newPercentage / 100) * duration);
    }
  };

  return (
    <div className="w-full mb-2">
      <DualRangeSlider
        label={(value) => <span>{formatTime(value ?? 0)}</span>}
        value={[widthPercentage]}
        onValueChange={handleSliderChange}
        min={0}
        max={100}
        step={1}
      />
    </div>
  );
};
