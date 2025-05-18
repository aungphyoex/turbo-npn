'use client';

import SignOut from '@/components/auth/sign-out';
import { Button } from '@repo/shadcn/button';
import { cn } from '@repo/shadcn/lib/utils';
import {
  Shield,
  Smartphone,
  User as UserIcon,
  UserPenIcon,
} from '@repo/shadcn/lucide-react';
import { User } from 'next-auth';
import Link from 'next/link';
import { usePathname } from 'next/navigation';

const ProfileSidebar = ({ user }: { user: User }) => {
  const menuItems = [
    {
      id: 'profile',
      label: 'Profile',
      icon: UserIcon,
      href: `/p/${user.username}`,
    },
    {
      id: 'general',
      label: 'General',
      icon: UserPenIcon,
      href: `/p/${user.username}/general`,
    },
    {
      id: 'security',
      label: 'Security and Login',
      icon: Shield,
      href: `/p/${user.username}/security`,
    },
    {
      id: 'sessions',
      label: 'Active Sessions',
      icon: Smartphone,
      href: `/p/${user.username}/sessions`,
    },
  ];
  const pathname = usePathname();
  return (
    <div className="bg-card rounded-lg shadow p-4">
      <h2 className="font-semibold text-lg mb-4">Settings</h2>
      <nav className="space-y-1">
        {menuItems.map((item) => {
          const Icon = item.icon;
          return (
            <Button
              key={item.id}
              variant={pathname === item.href ? 'secondary' : 'ghost'}
              className={cn(
                `w-full justify-start`,
                pathname === item.href && 'bg-secondary',
              )}
              asChild
            >
              <Link href={item.href}>
                <Icon className="mr-2 h-4 w-4" />
                {item.label}
              </Link>
            </Button>
          );
        })}

        <SignOut />
      </nav>
    </div>
  );
};

export default ProfileSidebar;
