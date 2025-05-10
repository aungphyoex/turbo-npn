import { Button } from '@repo/shadcn/button';
import { RotateCcw, RotateCw } from 'lucide-react';
import { useEffect, useState } from 'react';

type OrientationLockType = 'portrait' | 'landscape';

const ScreenOrientation = () => {
  const [orientation, setOrientation] =
    useState<OrientationLockType>('portrait');
  const [isFullscreen, setIsFullscreen] = useState(false);

  // Listen for fullscreen change
  useEffect(() => {
    const handleFullscreenChange = () => {
      setIsFullscreen(!!document.fullscreenElement);
    };

    document.addEventListener('fullscreenchange', handleFullscreenChange);
    return () => {
      document.removeEventListener('fullscreenchange', handleFullscreenChange);
    };
  }, []);

  const toggleOrientation = async () => {
    try {
      const newOrientation: OrientationLockType =
        orientation === 'landscape' ? 'portrait' : 'landscape';

      if (!document.fullscreenElement) {
        console.warn('Not in fullscreen, orientation change skipped.');
        return;
      }

      const orientationAPI = screen.orientation;
      const lockFn = (orientationAPI as any).lock;
      if (typeof lockFn === 'function') {
        await lockFn.call(orientationAPI, newOrientation);
        setOrientation(newOrientation);
      } else {
        console.warn('Orientation lock not supported.');
        return;
      }
    } catch (err) {
      console.error('Orientation toggle failed:', err);
      return;
    }
  };

  if (!isFullscreen) return null; // Hide button if not fullscreen

  return (
    <Button
      onClick={toggleOrientation}
      variant="ghost"
      size="icon"
      className="size-7 hover:bg-transparent focus:outline-none focus-visible:ring-0 text-secondary dark:text-secondary-foreground"
      title={`Switch to ${orientation === 'landscape' ? 'portrait' : 'landscape'}`}
    >
      {orientation === 'landscape' ? (
        <RotateCcw className="size-4" />
      ) : (
        <RotateCw className="size-4" />
      )}
    </Button>
  );
};

export default ScreenOrientation;
