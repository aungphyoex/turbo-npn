'use client';

import React, { type SyntheticEvent } from 'react';

import ReactCrop, {
  centerCrop,
  makeAspectCrop,
  type Crop,
  type PixelCrop,
} from 'react-image-crop';

import { Avatar, AvatarFallback, AvatarImage } from '@repo/shadcn/avatar';
import { Button } from '@repo/shadcn/button';
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogFooter,
} from '@repo/shadcn/dialog';
import { CropIcon, Trash2Icon } from 'lucide-react';
import { FileWithPath } from 'react-dropzone';
import 'react-image-crop/dist/ReactCrop.css';

export type FileWithPreview = FileWithPath & {
  preview: string;
};

interface ImageCropperProps {
  dialogOpen: boolean;
  setDialogOpen: React.Dispatch<React.SetStateAction<boolean>>;
  selectedFile: FileWithPreview | null;
  setSelectedFile: React.Dispatch<React.SetStateAction<FileWithPreview | null>>;
  onCropDone?: (file: File, previewUrl: string) => void; // optional callback
}

export function ImageCropper({
  dialogOpen,
  setDialogOpen,
  selectedFile,
  setSelectedFile,
  onCropDone,
}: ImageCropperProps) {
  const aspect = 1;

  const imgRef = React.useRef<HTMLImageElement | null>(null);

  const [crop, setCrop] = React.useState<Crop>();
  const [croppedImage, setCroppedImage] = React.useState<string>('');
  const [croppedFile, setCroppedFile] = React.useState<File | null>(null);

  function onImageLoad(e: SyntheticEvent<HTMLImageElement>) {
    if (aspect) {
      const { width, height } = e.currentTarget;
      setCrop(centerAspectCrop(width, height, aspect));
    }
  }

  async function onCropComplete(crop: PixelCrop) {
    if (imgRef.current && crop.width && crop.height) {
      try {
        const file = await getCroppedImg(imgRef.current, crop);
        const previewUrl = URL.createObjectURL(file);
        setCroppedFile(file);
        setCroppedImage(previewUrl);
      } catch (error) {
        console.error('Failed to crop image', error);
      }
    }
  }

  async function onCrop() {
    if (croppedFile && croppedImage) {
      if (onCropDone) {
        onCropDone(croppedFile, croppedImage);
      }
      setDialogOpen(false);
    } else {
      alert('Crop is not ready yet.');
    }
  }

  // Cleanup the preview URL when component unmounts or image changes
  React.useEffect(() => {
    return () => {
      if (croppedImage) {
        URL.revokeObjectURL(croppedImage);
      }
    };
  }, [croppedImage]);

  return (
    <Dialog open={dialogOpen} onOpenChange={setDialogOpen}>
      <DialogContent className="p-0 gap-0">
        <div className="p-6 size-full">
          <ReactCrop
            crop={crop}
            onChange={(_, percentCrop) => setCrop(percentCrop)}
            onComplete={(c) => onCropComplete(c)}
            aspect={aspect}
            className="w-full"
          >
            <Avatar className="size-full rounded-none">
              <AvatarImage
                ref={imgRef}
                className="size-full rounded-none "
                alt="Image Cropper Shell"
                src={selectedFile?.preview}
                onLoad={onImageLoad}
              />
              <AvatarFallback className="size-full min-h-[460px] rounded-none">
                Loading...
              </AvatarFallback>
            </Avatar>
          </ReactCrop>
        </div>
        <DialogFooter className="p-6 pt-0 justify-center ">
          <DialogClose asChild>
            <Button
              size={'sm'}
              type="reset"
              className="w-fit"
              variant={'outline'}
              onClick={() => {
                setSelectedFile(null);
              }}
            >
              <Trash2Icon className="mr-1.5 size-4" />
              Cancel
            </Button>
          </DialogClose>
          <Button type="submit" size={'sm'} className="w-fit" onClick={onCrop}>
            <CropIcon className="mr-1.5 size-4" />
            Crop
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// Center the crop using aspect ratio
export function centerAspectCrop(
  mediaWidth: number,
  mediaHeight: number,
  aspect: number,
): Crop {
  return centerCrop(
    makeAspectCrop(
      {
        unit: '%',
        width: 50,
      },
      aspect,
      mediaWidth,
      mediaHeight,
    ),
    mediaWidth,
    mediaHeight,
  );
}

// Convert cropped canvas region into File object
async function getCroppedImg(
  image: HTMLImageElement,
  crop: PixelCrop,
): Promise<File> {
  const canvas = document.createElement('canvas');
  const scaleX = image.naturalWidth / image.width;
  const scaleY = image.naturalHeight / image.height;

  canvas.width = crop.width * scaleX;
  canvas.height = crop.height * scaleY;

  const ctx = canvas.getContext('2d');

  if (!ctx) {
    throw new Error('Canvas context is not available');
  }

  ctx.imageSmoothingEnabled = false;

  ctx.drawImage(
    image,
    crop.x * scaleX,
    crop.y * scaleY,
    crop.width * scaleX,
    crop.height * scaleY,
    0,
    0,
    crop.width * scaleX,
    crop.height * scaleY,
  );

  return new Promise((resolve, reject) => {
    canvas.toBlob(
      (blob) => {
        if (!blob) {
          reject(new Error('Canvas is empty'));
          return;
        }
        const file = new File([blob], `${Date.now()}.png`, {
          type: 'image/png',
        });
        resolve(file);
      },
      'image/png',
      1.0,
    );
  });
}

export * from 'react-dropzone';
