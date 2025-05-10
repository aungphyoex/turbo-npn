import React from 'react';

/**
 * Represents the available video size modes for controlling how the video fits in its container
 * - 'stretch': Stretches the video to fill the container (may distort aspect ratio)
 * - 'fit': Maintains aspect ratio while fitting within container
 * - 'crop': Fills container while maintaining aspect ratio (may crop edges)
 * - 'original': Displays video at its original size
 */
export type VideoSizeMode = 'stretch' | 'fit' | 'crop' | 'original';

/**
 * Props for the main VideoPlayer component
 */
export interface VideoPlayerProps {
  /** URL of the video to play */
  src: string;
  /** URL of the poster image to show before video plays */
  poster?: string;
  /** Additional CSS classes to apply to the container */
  className?: string;
  /** Whether to start playing automatically */
  autoPlay?: boolean;
  /** Whether to start muted */
  muted?: boolean;
  /** Whether to loop the video */
  loop?: boolean;
  /** Whether to show video controls */
  controls?: boolean;
  /** Keyboard controls*/
  keyboardControls?: boolean;
  /** Callback fired when video starts playing */
  onPlay?: () => void;
  /** Callback fired when video is paused */
  onPause?: () => void;
  /** Callback fired when video ends */
  onEnded?: () => void;
  /** Callback fired when playback position changes */
  onTimeUpdate?: (currentTime: number) => void;
  /** Callback fired when video duration is loaded */
  onDurationChange?: (duration: number) => void;
}

/**
 * Props for the VideoControls component
 */
export interface VideoControlsProps {
  /** Whether video is currently playing */
  isPlaying: boolean;
  /** Whether video is currently muted */
  isMuted: boolean;
  /** Current playback position in seconds */
  currentTime: number;
  /** Total video duration in seconds */
  duration: number;
  /** Whether video is in fullscreen mode */
  isFullscreen: boolean;
  /** Current playback speed multiplier */
  playbackRate: number;
  /** Current video size mode */
  sizeMode: VideoSizeMode;
  /** Function to toggle play/pause */
  onPlayPause: () => void;
  /** Function to toggle mute */
  onMute: () => void;
  /** Function to seek to specific time */
  onSeek: (time: number) => void;
  /** Function to skip backward */
  onSkipBackward: () => void;
  /** Function to skip forward */
  onSkipForward: () => void;
  /** Function to toggle fullscreen */
  onFullscreen: () => void;
  /** Function to change playback speed */
  onPlaybackRateChange: (rate: number) => void;
  /** Function to change size mode */
  setSizeMode: React.Dispatch<React.SetStateAction<VideoSizeMode>>;
}

/**
 * Props for the VideoTimeline component
 */
export interface VideoTimelineProps {
  /** Current playback position in seconds */
  currentTime: number;
  /** Total video duration in seconds */
  duration: number;
  /** Function to seek to specific time */
  onSeek: (time: number) => void;
}

/**
 * Props for the VideoResizer component
 */
export interface VideoResizerProps {
  /** Current video size mode */
  sizeMode: VideoSizeMode;
  /** Function to change size mode */
  setSizeMode: React.Dispatch<React.SetStateAction<VideoSizeMode>>;
}

/**
 * Props for the KeyboardControls component
 */
export interface KeyboardControlsProps {
  /** Whether video is currently playing */
  isPlaying: boolean;
  /** Whether video is currently muted */
  isMuted: boolean;
  /** Whether video is in fullscreen mode */
  isFullscreen: boolean;
}
