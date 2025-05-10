'use client';

import { Button } from '@repo/shadcn/button';
import {
  Drawer,
  DrawerContent,
  DrawerHeader,
  DrawerTitle,
  DrawerTrigger,
} from '@repo/shadcn/drawer';
import { cn } from '@repo/shadcn/lib/utils';
import { ChevronDown } from 'lucide-react';
import React, { useState } from 'react';

interface MobileToolbarGroupProps {
  label: string;
  children: React.ReactNode;
  className?: string;
}

export const MobileToolbarGroup = ({
  label,
  children,
  className,
}: MobileToolbarGroupProps) => {
  const [isOpen, setIsOpen] = useState(false);

  const closeDrawer = () => setIsOpen(false);

  return (
    <Drawer open={isOpen} onOpenChange={setIsOpen}>
      <DrawerTrigger asChild>
        <Button
          variant="ghost"
          size="sm"
          className={cn('h-8 w-max gap-1 px-3 font-normal', className)}
        >
          {label}
          <ChevronDown className="h-4 w-4" />
        </Button>
      </DrawerTrigger>
      <DrawerContent>
        <DrawerHeader>
          <DrawerTitle className="text-start">{label}</DrawerTitle>
        </DrawerHeader>
        <div className="flex flex-col p-4">
          {React.Children.map(children, (child) =>
            React.isValidElement(child)
              ? React.cloneElement(child, { closeDrawer } as {
                  closeDrawer: () => void;
                })
              : child,
          )}
        </div>
      </DrawerContent>
    </Drawer>
  );
};

export const MobileToolbarItem = ({
  children,
  active,
  onClick,
  closeDrawer,
  ...props
}: React.ButtonHTMLAttributes<HTMLButtonElement> & {
  active?: boolean;
  closeDrawer?: () => void;
}) => (
  <button
    className={cn(
      'flex w-full items-center rounded-md px-4 py-2 text-sm transition-colors hover:bg-accent',
      active && 'bg-accent',
    )}
    onClick={(e) => {
      onClick?.(e);
      setTimeout(() => {
        closeDrawer?.();
      }, 100);
    }}
    {...props}
  >
    {children}
  </button>
);
