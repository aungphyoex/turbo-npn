import { VideoSizeMode } from '@repo/shadcn/video/player';
import { clsx, type ClassValue } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Converts seconds into a time string (HH:MM:SS or MM:SS).
 *
 * @param seconds - The number of seconds to format
 * @returns Formatted time string
 */
export const formatTime = (seconds: number): string => {
  if (isNaN(seconds)) return '00:00';

  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);

  if (hours > 0) {
    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  }

  return `${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
};

/**
 * Maps a video size mode to a corresponding CSS object-fit value.
 *
 * @param sizeMode - Video display mode
 * @returns CSS objectFit string
 */
export const getObjectFit = (
  sizeMode: VideoSizeMode,
): React.CSSProperties['objectFit'] => {
  switch (sizeMode) {
    case 'stretch':
      return 'fill';
    case 'fit':
      return 'contain';
    case 'crop':
      return 'cover';
    case 'original':
      return 'none';
  }
};

/**
 * Returns dynamic video styles based on the selected size mode.
 *
 * @param sizeMode - Current video size mode
 * @returns A React CSSProperties object
 */
export const getVideoStyles = (
  sizeMode: VideoSizeMode,
): React.CSSProperties => ({
  width: sizeMode === 'original' ? 'auto' : '100%',
  height: sizeMode === 'original' ? 'auto' : '100%',
  objectFit: getObjectFit(sizeMode),
  outline: 'none',
  userSelect: 'none',
  WebkitUserSelect: 'none',
  MozUserSelect: 'none',
  msUserSelect: 'none',
  WebkitTouchCallout: 'none',
});
