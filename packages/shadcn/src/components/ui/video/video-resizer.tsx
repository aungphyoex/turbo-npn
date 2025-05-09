import { Button } from '@repo/shadcn/button';
import { cn } from '@repo/shadcn/lib/utils';
import { VideoSizeMode } from '@repo/shadcn/video/player';
import {
  MoveDiagonal,
  ScanSearch,
  StretchHorizontal,
  ZoomIn,
} from 'lucide-react';
import { Dispatch, ReactNode, SetStateAction, useState } from 'react';

const modeButtons: { mode: VideoSizeMode; icon: ReactNode; label: string }[] = [
  { mode: 'fit', icon: <MoveDiagonal className="size-3" />, label: 'Fit' },
  {
    mode: 'stretch',
    icon: <StretchHorizontal className="size-3" />,
    label: 'Stretch',
  },
  { mode: 'crop', icon: <ZoomIn className="size-3" />, label: 'Crop' },
  { mode: 'original', icon: <ScanSearch className="size-3" />, label: '100%' },
];

const VideoResizer = ({
  sizeMode,
  setSizeMode,
}: {
  sizeMode: VideoSizeMode;
  setSizeMode: Dispatch<SetStateAction<VideoSizeMode>>;
}) => {
  const currentIndex = modeButtons.findIndex((b) => b.mode === sizeMode);
  const nextIndex = (currentIndex + 1) % modeButtons.length;
  const { icon } = modeButtons[nextIndex]!;
  const [showKeyHint, setShowKeyHint] = useState(false);
  return (
    <>
      <Button
        variant="ghost"
        size="icon"
        className={cn(
          'size-6 text-neutral-300 hover:bg-neutral-800 hover:text-neutral-300/80 focus:outline-none focus-visible:ring-0',
        )}
        onClick={() => {
          setSizeMode(modeButtons[nextIndex]!.mode);
          setShowKeyHint(true);
          setTimeout(() => {
            setShowKeyHint(false);
          }, 500);
        }}
        title={`Switch to ${modeButtons[nextIndex]!.label}`}
      >
        {icon}
      </Button>
      <div
        className={cn(
          'absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2',
          'bg-card-foreground rounded px-4 py-2 text-white text-center transition-opacity duration-300',
          showKeyHint ? 'opacity-100' : 'opacity-0',
        )}
      >
        <div className="flex gap-2 items-center justify-center">
          <div className="text-xs">{modeButtons[nextIndex]!.label}</div>
        </div>
      </div>
    </>
  );
};

export default VideoResizer;
