import { cn } from '@repo/shadcn/lib/utils';
import Image from 'next/image';

const LogoIcon = ({
  className,
  src,
  height,
  width,
}: {
  src?: string;
  className?: string;
  width?: number;
  height?: number;
}) => {
  return (
    <Image
      alt="logo icon"
      src={src ?? '/assets/logo/icon.svg'}
      height={height ?? 50}
      width={width ?? 50}
      priority
      fetchPriority="high"
      className={cn('object-contain', className)}
    />
  );
};

export default LogoIcon;
