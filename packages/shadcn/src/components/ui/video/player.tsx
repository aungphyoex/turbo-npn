'use client';
import { useMobile } from '@repo/shadcn/hooks/use-mobile';
import { cn, formatTime, getVideoStyles } from '@repo/shadcn/lib/utils';
import { KeyboardControls } from '@repo/shadcn/video/keyboard-controls';
import ScreenOrientation from '@repo/shadcn/video/screen-orientation';
import { VideoControls } from '@repo/shadcn/video/video-controls';
import { VideoTimeline } from '@repo/shadcn/video/video-timeline';
import React, { JSX, useCallback, useEffect, useRef, useState } from 'react';
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

/**
 * Index component renders a customizable video player with controls like play/pause, mute, fullscreen, and playback speed.
 * @param {VideoPlayerProps} props - Properties passed to the Index component
 * @returns {JSX.Element} Video player UI
 */
export const VideoPlayer: React.FC<VideoPlayerProps> = ({
  src,
  poster,
  className,
  autoPlay = false,
  muted = false,
  loop = false,
  controls: showDefaultControls = true,
  onPlay,
  onPause,
  onEnded,
  onTimeUpdate,
  onDurationChange,
}: VideoPlayerProps): JSX.Element => {
  const videoRef = useRef<HTMLVideoElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  // Local state variables for managing the video player's status
  const [isPlaying, setIsPlaying] = useState(false);
  const [isMuted, setIsMuted] = useState(muted);
  const [currentTime, setCurrentTime] = useState(0);
  const [duration, setDuration] = useState(0);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [playbackRate, setPlaybackRate] = useState(1);
  const [showControls, setShowControls] = useState(true);
  const [controlsTimeout, setControlsTimeout] = useState<NodeJS.Timeout | null>(
    null,
  );
  const [sizeMode, setSizeMode] = useState<VideoSizeMode>('stretch');

  const isMobile = useMobile();

  // Function to toggle between play and pause
  const togglePlay = () => {
    const video = videoRef.current;
    if (!video) return;

    // If duration is 0, set it to the video’s duration
    if (!duration) {
      setDuration(video.duration);
    }

    // Play or pause the video based on its current state
    if (video.paused) {
      video.play().then(() => {
        console.log('Video is playing...');
      });
    } else {
      video.pause();
      console.log('Video is paused...');
    }
  };

  // Function to toggle mute/unmute
  const toggleMute = useCallback(() => {
    const video = videoRef.current;
    if (!video) return;
    const newMutedState = !isMuted;
    video.muted = newMutedState;
    console.log('Video is ', newMutedState ? 'muted...' : 'unmuted...');
    setIsMuted(newMutedState);
  }, [isMuted]);

  // Function to seek to a specific time in the video
  const handleSeek = (seekTime: number) => {
    const video = videoRef.current;
    if (!video) return;
    video.currentTime = seekTime;
    console.log(`Video is seeking to ${formatTime(seekTime)}s`);
    setCurrentTime(seekTime);
  };

  // Function to skip forward by 10 seconds
  const skipForward = () => {
    const video = videoRef.current;
    if (!video) return;
    const newTime = Math.min(video.duration, video.currentTime + 10);
    video.currentTime = newTime;
    console.log(`Video is forward to ${formatTime(newTime)}s`);
    setCurrentTime(newTime);
  };

  // Function to skip backward by 10 seconds
  const skipBackward = () => {
    const video = videoRef.current;
    if (!video) return;
    const newTime = Math.max(0, video.currentTime - 10);
    video.currentTime = newTime;
    console.log(`Video is backward to ${formatTime(newTime)}s`);
    setCurrentTime(newTime);
  };

  // Function to toggle fullscreen mode
  const toggleFullscreen = () => {
    const container = containerRef.current;
    if (!container) return;

    if (!document.fullscreenElement) {
      container
        .requestFullscreen()
        .then(() => {
          setIsFullscreen(true);
        })
        .catch((err) => {
          console.error(
            `Error attempting to enable fullscreen: ${err.message}`,
          );
        });
    } else {
      document
        .exitFullscreen()
        .then(() => {
          setIsFullscreen(false);
        })
        .catch((err) => {
          console.error(`Error attempting to exit fullscreen: ${err.message}`);
        });
    }
    console.log('Fullscreen!!!');
  };

  // Function to handle playback rate changes
  const handlePlaybackRateChange = (rate: number) => {
    const video = videoRef.current;
    if (!video) return;

    video.playbackRate = rate;
    console.log(`Video playback rate change to ${rate}x`);
    setPlaybackRate(rate);
  };

  // Effect hook to initialize video properties and add event listeners
  useEffect(() => {
    const video = videoRef.current;
    if (!video) return;

    // Set video duration if not already set
    if (!duration) {
      setDuration(video.duration);
    }

    // Remove the default controls attribute
    video.removeAttribute('controls');

    // Set the mute state
    video.muted = muted;

    // Handle time update and update the current time
    const handleTimeUpdate = () => {
      console.log(`Video time is updated to ${formatTime(video.currentTime)}`);
      setCurrentTime(video.currentTime);
      if (onTimeUpdate) onTimeUpdate(video.currentTime);
    };

    // Event listeners for play, pause, and end events
    const handlePlay = () => {
      console.log('Video is playing...');
      setIsPlaying(true);
      if (onPlay) onPlay();
    };

    const handlePause = () => {
      console.log('Video is paused...');
      setIsPlaying(false);
      if (onPause) onPause();
    };

    const handleEnded = () => {
      console.log('Video has ended...');
      setIsPlaying(false);
      if (onEnded) onEnded();
    };

    // Prevent right-click and double-click on video
    const handleContextMenu = (e: MouseEvent) => e.preventDefault();
    const handleDoubleClick = (e: MouseEvent) => e.preventDefault();

    // Add event listeners
    video.addEventListener('contextmenu', handleContextMenu);
    video.addEventListener('dblclick', handleDoubleClick);
    video.addEventListener('timeupdate', handleTimeUpdate);
    video.addEventListener('play', handlePlay);
    video.addEventListener('pause', handlePause);
    video.addEventListener('ended', handleEnded);

    return () => {
      video.removeEventListener('contextmenu', handleContextMenu);
      video.removeEventListener('dblclick', handleDoubleClick);
      video.removeEventListener('timeupdate', handleTimeUpdate);
      video.removeEventListener('play', handlePlay);
      video.removeEventListener('pause', handlePause);
      video.removeEventListener('ended', handleEnded);
    };
  }, [muted, onDurationChange, onTimeUpdate, onPlay, onPause, onEnded]);

  // Effect hook to add keyboard controls
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      // Ignore if user is typing in an input field or if control/alt/meta keys are pressed
      if (
        document.activeElement instanceof HTMLInputElement ||
        document.activeElement instanceof HTMLTextAreaElement ||
        e.ctrlKey ||
        e.altKey ||
        e.metaKey
      ) {
        return;
      }

      // Handle keyboard shortcuts
      switch (e.key) {
        case ' ': // Space for play/pause
          e.preventDefault();
          togglePlay();
          break;
        case 'k': // K for play/pause alternative
          e.preventDefault();
          togglePlay();
          break;
        case 'm': // M for mute/unmute
          e.preventDefault();
          toggleMute();
          break;
        case 'f': // F for fullscreen toggle
          e.preventDefault();
          toggleFullscreen();
          break;
        case 'ArrowLeft': // Left arrow for seeking backward
          e.preventDefault();
          skipBackward();
          break;
        case 'ArrowRight': // Right arrow for seeking forward
          e.preventDefault();
          skipForward();
          break;
        default:
          // Number keys (0-9) for jumping to a percentage of the video
          const num = Number.parseInt(e.key);
          if (!isNaN(num) && num >= 0 && num <= 9) {
            e.preventDefault();
            const seekTime = (duration * num) / 10;
            handleSeek(seekTime);
          }
          break;
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [
    currentTime,
    duration,
    isFullscreen,
    togglePlay,
    toggleMute,
    toggleFullscreen,
    handleSeek,
    skipBackward,
    skipForward,
  ]);

  // Effect hook for handling the auto-hide of video controls
  useEffect(() => {
    if (!isMobile) {
      const handleMouseMove = () => {
        setShowControls(true);

        if (controlsTimeout) {
          clearTimeout(controlsTimeout);
        }

        const timeout = setTimeout(() => {
          if (isPlaying) {
            setShowControls(false);
          }
        }, 10000000);

        setControlsTimeout(timeout);
      };

      const container = containerRef.current;
      if (container) {
        container.addEventListener('mousemove', handleMouseMove);
        container.addEventListener('mouseleave', () => {
          if (isPlaying) {
            // setShowControls(false);
          }
        });
      }

      return () => {
        if (container) {
          container.removeEventListener('mousemove', handleMouseMove);
          container.removeEventListener('mouseleave', () => {});
        }

        if (controlsTimeout) {
          clearTimeout(controlsTimeout);
        }
      };
    }
  }, [isPlaying, controlsTimeout, isMobile]);

  return (
    <div
      ref={containerRef}
      className={cn(
        'relative overflow-hidden grid place-items-center bg-black/10 backdrop-blur-sm',
        className,
      )}
    >
      <>
        <video
          ref={videoRef}
          src={src}
          poster={poster}
          autoPlay={autoPlay}
          muted={muted}
          loop={loop}
          playsInline
          preload="metadata"
          className="size-full block"
          onClick={togglePlay}
          style={getVideoStyles(sizeMode)}
        />

        {/* Large play button in the middle */}
        <div
          className={cn(
            'absolute inset-0 flex items-center justify-center cursor-pointer transition-opacity duration-300',
            isPlaying ? 'opacity-0 pointer-events-none' : 'opacity-100',
          )}
          onClick={togglePlay}
        >
          <div className="bg-primary/50 hover:bg-primary rounded-full transform duration-500 transition-transform hover:scale-110 grid place-items-center">
            <div className="size-14">
              <svg
                xmlns="http://www.w3.org/2000/svg"
                width="60"
                height="60"
                fill="none"
              >
                <circle cx="30" cy="30" r="30" fill="#fff"></circle>
                <path fill="#000" d="M22.5 40.5v-21L42 30z"></path>
              </svg>
            </div>
          </div>
        </div>
        {showControls && (
          <div
            className={cn(
              'absolute inset-x-0 top-4 flex lg:hidden items-center justify-end pr-5 cursor-pointer transition-opacity duration-300',
              isPlaying ? 'opacity-0 pointer-events-none' : 'opacity-100',
            )}
          >
            <ScreenOrientation />
          </div>
        )}
        {/* Controls overlay */}
        {showDefaultControls && (
          <div
            className={cn(
              'absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black/90 to-black/0 p-2 transition-opacity duration-300',
              showControls ? 'opacity-100' : 'opacity-0',
            )}
          >
            <VideoTimeline
              currentTime={currentTime}
              duration={duration}
              onSeek={handleSeek}
            />
            <VideoControls
              isPlaying={isPlaying}
              isMuted={isMuted}
              currentTime={currentTime}
              duration={duration}
              isFullscreen={isFullscreen}
              playbackRate={playbackRate}
              onPlayPause={togglePlay}
              onMute={toggleMute}
              sizeMode={sizeMode}
              setSizeMode={setSizeMode}
              onSeek={handleSeek}
              onSkipBackward={skipBackward}
              onSkipForward={skipForward}
              onFullscreen={toggleFullscreen}
              onPlaybackRateChange={handlePlaybackRateChange}
            />
          </div>
        )}
      </>
      <KeyboardControls
        isPlaying={isPlaying}
        isMuted={isMuted}
        isFullscreen={isFullscreen}
      />
    </div>
  );
};
