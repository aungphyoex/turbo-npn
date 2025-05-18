'use client';
import { cn } from '@repo/shadcn/lib/utils';
import { VideoPlayerProps, VideoSizeMode } from '@repo/shadcn/lib/video-type';
import { formatTime, getVideoStyles } from '@repo/shadcn/lib/video-utils';
import ScreenOrientation from '@repo/shadcn/video/screen-orientation';
import { VideoControls } from '@repo/shadcn/video/video-controls';
import { VideoTimeline } from '@repo/shadcn/video/video-timeline';
import { delay } from 'motion';
import { AnimatePresence } from 'motion/react';
import * as motion from 'motion/react-client';
import React, { JSX, useCallback, useEffect, useRef, useState } from 'react';

/**
 * Use debounce hook
 * @param value - The value to debounce
 * @param duration - The duration in seconds to debounce the value
 * @returns The debounced value
 */
function useDebouncedState<T>(value: T, duration: number = 0.2): T {
  const [debouncedValue, setDebouncedValue] = useState<T>(value);
  useEffect(() => {
    return delay(() => setDebouncedValue(value), duration);
  }, [value, duration]);
  return debouncedValue;
}

const iconVariants = {
  initial: { opacity: 0, scale: 0.8 },
  animate: { opacity: 1, scale: 1 },
  exit: { opacity: 0, scale: 0.8 },
};

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
  keyboardControls,
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
  const [sizeMode, setSizeMode] = useState<VideoSizeMode>('stretch');

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

    // Set show controls initial state is false
    setShowControls(false);

    // Set the mute state
    video.muted = muted;

    // Handle time update and update the current time
    const handleTimeUpdate = () => {
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
    video.addEventListener('load', () => {
      console.log('video is loading');
    });
    video.addEventListener('canplay', () => {
      console.log('video is ready to play');
    });
    return () => {
      video.removeEventListener('contextmenu', handleContextMenu);
      video.removeEventListener('dblclick', handleDoubleClick);
      video.removeEventListener('timeupdate', handleTimeUpdate);
      video.removeEventListener('play', handlePlay);
      video.removeEventListener('pause', handlePause);
      video.removeEventListener('ended', handleEnded);
    };
  }, [muted, onDurationChange, onTimeUpdate, onPlay, onPause, onEnded]);

  useEffect(() => {
    if (!keyboardControls) return;

    const isTyping = (el: Element | null): boolean =>
      el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement;

    const handleNumberKey = (key: string) => {
      const num = Number.parseInt(key);
      if (!isNaN(num) && num >= 0 && num <= 9) {
        const seekTime = (duration * num) / 10;
        handleSeek(seekTime);
      }
    };

    const keyActions: Record<string, () => void> = {
      ' ': togglePlay,
      k: togglePlay,
      m: toggleMute,
      f: toggleFullscreen,
      ArrowLeft: skipBackward,
      ArrowRight: skipForward,
    };

    const handleKeyDown = (e: KeyboardEvent) => {
      if (
        isTyping(document.activeElement) ||
        e.ctrlKey ||
        e.altKey ||
        e.metaKey
      ) {
        return;
      }

      if (keyActions[e.key]) {
        e.preventDefault();
        console.log(e.key);
        keyActions[e.key]!();
      } else {
        handleNumberKey(e.key);
      }
    };

    window.addEventListener('keyup', handleKeyDown);
    return () => window.removeEventListener('keyup', handleKeyDown);
  }, [
    keyboardControls,
    duration,
    togglePlay,
    toggleMute,
    toggleFullscreen,
    handleSeek,
    skipBackward,
    skipForward,
  ]);

  const debouncedSizeMode = useDebouncedState(sizeMode);

  return (
    <AnimatePresence>
      <div
        ref={containerRef}
        className={cn(
          'relative overflow-hidden grid place-items-center bg-black/10 backdrop-blur-sm',
          className,
        )}
      >
        <>
          <motion.video
            ref={videoRef}
            src={src}
            poster={poster}
            autoPlay={autoPlay}
            muted={muted}
            loop={loop}
            playsInline
            preload="metadata"
            className="size-full block"
            onClick={() => setShowControls((prevState) => !prevState)}
            transition={{ duration: 0.5 }}
            style={getVideoStyles(debouncedSizeMode)}
          />

          {/* Large play button in the middle */}
          <div
            onClick={() => {
              if (showControls) setShowControls((prevState) => !prevState);
            }}
            className={cn(
              'absolute inset-0 flex items-center justify-center  transition-opacity duration-300',
              isPlaying ? 'opacity-0 pointer-events-none' : 'opacity-100',
              showControls && 'opacity-100 pointer-events-auto',
            )}
          >
            <motion.div
              onClick={(e) => {
                e.stopPropagation();
                togglePlay();
              }}
              whileHover={{ scale: 1.1 }}
              whileTap={{ scale: 0.95 }}
              className="bg-primary/50 hover:bg-primary rounded-full text-white p-3 grid place-items-center cursor-pointer focus-visible:outline-0 focus-visible:border-0"
            >
              <AnimatePresence mode="wait" initial={false}>
                {isPlaying ? (
                  <motion.svg
                    key="pause"
                    xmlns="http://www.w3.org/2000/svg"
                    width="24"
                    height="24"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    className="lucide lucide-pause-icon lucide-pause"
                    variants={iconVariants}
                    initial="initial"
                    animate="animate"
                    exit="exit"
                    transition={{ duration: 0.2 }}
                  >
                    <rect x="14" y="4" width="4" height="16" rx="1" />
                    <rect x="6" y="4" width="4" height="16" rx="1" />
                  </motion.svg>
                ) : (
                  <motion.svg
                    key="play"
                    xmlns="http://www.w3.org/2000/svg"
                    width="24"
                    height="24"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="2"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    className="lucide lucide-play-icon lucide-play"
                    variants={iconVariants}
                    initial="initial"
                    animate="animate"
                    exit="exit"
                    transition={{ duration: 0.2 }}
                  >
                    <polygon points="6 3 20 12 6 21 6 3" />
                  </motion.svg>
                )}
              </AnimatePresence>
            </motion.div>
          </div>
          {showDefaultControls && (
            <motion.div
              initial={{ opacity: 0, x: 20 }}
              animate={{
                opacity: showControls ? 1 : 0,
                x: showControls ? 0 : 20,
              }}
              exit={{ opacity: 0, x: 20 }}
              transition={{ duration: 0.3 }}
              className="absolute inset-x-0 px-6 flex justify-end py-3 items-center top-0"
            >
              <ScreenOrientation />
            </motion.div>
          )}
          <>
            {showDefaultControls && (
              <motion.div
                initial={{ opacity: 0, y: 20 }}
                animate={{
                  opacity: showControls ? 1 : 0,
                  y: showControls ? 0 : 20,
                }}
                exit={{ opacity: 0, y: 20 }}
                transition={{ duration: 0.3 }}
                className="absolute bottom-0 left-0 right-0 p-2 px-6 group"
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
              </motion.div>
            )}
          </>
        </>
      </div>
    </AnimatePresence>
  );
};
