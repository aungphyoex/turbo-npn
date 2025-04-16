import { Button, buttonVariants } from '@repo/shadcn/button';
import { cn } from '@repo/shadcn/lib/utils';
import { IconLoader } from '@tabler/icons-react';
import type { VariantProps } from 'class-variance-authority';
import * as React from 'react';

const SubmitButton = ({
  className,
  variant,
  size,
  asChild = false,
  isLoading,
  name,
  ...props
}: React.ComponentProps<'button'> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean;
    isLoading: boolean;
  }) => {
  return (
    <Button
      type="submit"
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
      disabled={isLoading}
    >
      {isLoading ? (
        <>
          <IconLoader className={'animate-spin'} stroke={2} />
          Waiting...
        </>
      ) : (
        name
      )}
    </Button>
  );
};

export default SubmitButton;
