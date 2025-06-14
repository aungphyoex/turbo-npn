'use client';

import SignOut from '@/components/auth/sign-out';
import { buttonVariants } from '@repo/shadcn/button';
import { cn } from '@repo/shadcn/lib/utils';
import {
  Palette,
  Shield,
  Smartphone,
  User as UserIcon,
  UserPenIcon,
} from '@repo/shadcn/lucide';
import { TabsList, TabsTrigger } from '@repo/shadcn/tabs';

const ProfileSidebar = () => {
  const menuItems = [
    {
      id: 'profile',
      label: 'Profile',
      icon: UserIcon,
    },
    {
      id: 'general',
      label: 'General',
      icon: UserPenIcon,
    },
    {
      id: 'security',
      label: 'Security and Login',
      icon: Shield,
    },
    {
      id: 'sessions',
      label: 'Active Sessions',
      icon: Smartphone,
    },
    {
      id: 'appearance',
      label: 'Appearance',
      icon: Palette,
    },
  ];
  return (
    <div className="w-full bg-card text-card-foreground rounded-xl border shadow-sm p-4">
      <h2 className="font-semibold text-lg mb-4">Settings</h2>
      <TabsList className="grid gap-1 grid-cols-1 w-full px-0 h-auto bg-card p-0">
        {menuItems.map((item) => {
          const Icon = item.icon;
          return (
            <TabsTrigger
              key={item.id}
              className={cn(
                buttonVariants({
                  variant: 'ghost',
                  class:
                    'min-w-full justify-start data-[state=active]:bg-secondary data-[state=active]:text-secondary-foreground data-[state=active]:shadow-xs data-[state=active]:hover:bg-secondary/80',
                }),
              )}
              value={item.id}
            >
              <Icon className="mr-2 h-4 w-4" />
              {item.label}
            </TabsTrigger>
          );
        })}

        <SignOut />
      </TabsList>
    </div>
  );
};

export default ProfileSidebar;
