import { Button } from '@repo/shadcn/button';
import { RotateCcw, RotateCw } from 'lucide-react';
import { useState } from 'react';

type OrientationLockType = 'portrait' | 'landscape';

const ScreenOrientation = () => {
  const [orientation, setOrientation] =
    useState<OrientationLockType>('portrait');

  const toggleOrientation = async () => {
    try {
      const newOrientation: OrientationLockType =
        orientation === 'landscape' ? 'portrait' : 'landscape';

      // Enter fullscreen if needed
      if (!document.fullscreenElement) {
        await document.documentElement.requestFullscreen();
      }

      // Call orientation.lock dynamically
      const orientationAPI = screen.orientation;
      const lockFn = (orientationAPI as any).lock;
      if (typeof lockFn === 'function') {
        await lockFn.call(orientationAPI, newOrientation);
        setOrientation(newOrientation);
      } else {
        console.warn('Orientation lock not supported.');
      }
    } catch (err) {
      console.error('Orientation toggle failed:', err);
    }
  };

  return (
    <Button
      onClick={toggleOrientation}
      variant="default"
      size="icon"
      className="size-6 text-neutral-300 hover:bg-neutral-800 hover:text-neutral-300/80 focus:outline-none focus-visible:ring-0"
      title={`Switch to ${orientation === 'landscape' ? 'portrait' : 'landscape'}`}
    >
      {orientation === 'landscape' ? (
        <RotateCcw size={24} />
      ) : (
        <RotateCw size={24} />
      )}
    </Button>
  );
};

export default ScreenOrientation;
